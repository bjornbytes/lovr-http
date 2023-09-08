#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef void fn_header(void* userdata, const char* name, size_t nameLength, const char* value, size_t valueLength);

typedef struct {
  const char* url;
  const char* method;
  const char** headers;
  uint32_t headerCount;
  const char* data;
  size_t size;
} http_request_t;

typedef struct {
  const char* error;
  uint32_t status;
  char* data;
  size_t size;
  fn_header* header_cb;
  void* userdata;
} http_response_t;

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>

static HINTERNET internet;

static void http_init(void) {
  internet = InternetOpen("LOVR", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
}

static void http_destroy(void) {
  InternetCloseHandle(internet);
}

static bool http_request(http_request_t* req, http_response_t* res) {
  if (req->size > UINT32_MAX) {
    res->error = "request data too large";
    return false;
  }

  if (!internet) {
    res->error = "unknown error";
    return false;
  }

  // parse URL
  size_t length = strlen(req->url);
  const char* url = req->url;
  bool https = false;

  if (length > 8 && !memcmp(url, "https://", 8)) {
    https = true;
    length -= 8;
    url += 8;
  } else if (length > 7 && !memcmp(url, "http://", 7)) {
    length -= 7;
    url += 7;
  } else {
    res->error = "invalid url scheme";
    return false;
  }

  if (strchr(url, '@')) {
    res->error = "invalid url";
    return false;
  }

  char* path = strchr(url, '/');
  size_t hostLength = path ? path - url : length;

  INTERNET_PORT port = https ? 443 : 80;
  char* colon = memchr(url, ':', hostLength);

  if (colon) {
    hostLength = colon - url;

    port = 0;
    for (char* p = colon + 1; *p && *p != '/'; p++) {
      if (*p < '0' || *p > '9') {
        res->error = "invalid url port";
        return false;
      } else {
        port *= 10;
        port += *p - '0';
      }
    }

    if (port <= 0 || port >= 65536) {
      res->error = "invalid url port";
      return false;
    }
  }

  char host[256];
  if (sizeof(host) > hostLength) {
    memcpy(host, url, hostLength);
    host[hostLength] = '\0';
  } else {
    res->error = "invalid url host";
    return false;
  }

  // connection
  HINTERNET connection = InternetConnectA(internet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
  if (!connection) {
    res->error = "system error while setting up request";
    return false;
  }

  // setup request
  const char* method = req->method ? req->method : (req->data ? "POST" : "GET");
  DWORD flags = 0;
  flags |= INTERNET_FLAG_NO_AUTH;
  flags |= INTERNET_FLAG_NO_CACHE_WRITE;
  flags |= INTERNET_FLAG_NO_COOKIES;
  flags |= INTERNET_FLAG_NO_UI;
  flags |= https ? INTERNET_FLAG_SECURE : 0;
  HINTERNET request = HttpOpenRequestA(connection, method, path, NULL, NULL, NULL, flags, 0);
  if (!request) {
    InternetCloseHandle(connection);
    res->error = "system error while setting up request";
    return false;
  }

  // request headers
  if (req->headerCount >= 0) {
    char* header = NULL;
    size_t capacity = 0;
    for (uint32_t i = 0; i < req->headerCount; i++) {
      const char* name = *req->headers++;
      const char* value = *req->headers++;
      const char* format = "%s: %s\r\n";
      int length = snprintf(NULL, 0, format, name, value);
      if (length > UINT32_MAX) continue;
      if (length + 1 > capacity) {
        capacity = length + 1;
        header = realloc(header, capacity);
        if (!header) {
          InternetCloseHandle(connection);
          res->error = "out of memory";
          return false;
        }
      }
      sprintf(header, format, name, value);
      HttpAddRequestHeadersA(request, header, (DWORD) length, HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE);
    }
    free(header);
  }

  // do the thing
  bool success = HttpSendRequestA(request, NULL, 0, (void*) req->data, (DWORD) req->size);
  if (!success) {
    InternetCloseHandle(connection);
    res->error = "system error while sending request";
    return false;
  }

  // status
  DWORD status;
  DWORD bufferSize = sizeof(status);
  DWORD index = 0;
  HttpQueryInfoA(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &bufferSize, &index);
  res->status = status;
  index = 0;

  // response headers
  char stack[1024];
  char* buffer = stack;
  bufferSize = sizeof(stack);
  success = HttpQueryInfoA(request, HTTP_QUERY_RAW_HEADERS, buffer, &bufferSize, &index);
  if (!success) {
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      buffer = malloc(bufferSize);

      if (!buffer) {
        InternetCloseHandle(request);
        InternetCloseHandle(connection);
        res->error = "out of memory";
        return false;
      }

      success = HttpQueryInfoA(request, HTTP_QUERY_RAW_HEADERS, buffer, &bufferSize, &index);
    }

    if (!success) {
      if (buffer != stack) free(buffer);
      InternetCloseHandle(request);
      InternetCloseHandle(connection);
      res->error = "system error while parsing headers";
      return false;
    }
  }

  char* header = buffer;
  while (*header) {
    size_t length = strlen(header);
    char* colon = strchr(header, ':');
    if (colon && colon != header && length >= (size_t) (colon - header + 2)) {
      char* name = header;
      char* value = colon + 2;
      size_t nameLength = colon - header;
      size_t valueLength = length - (colon - header + 2);
      res->header_cb(res->userdata, name, nameLength, value, valueLength);
    }
    header += length + 1;
  }

  if (buffer != stack) {
    free(buffer);
  }

  // body
  res->data = NULL;
  res->size = 0;

  for (;;) {
    DWORD bytes = 0;
    if (!InternetQueryDataAvailable(request, &bytes, 0, 0)) {
      free(res->data);
      InternetCloseHandle(request);
      InternetCloseHandle(connection);
      res->error = "system error while reading response";
      return false;
    }

    if (bytes == 0) {
      break;
    }

    res->data = realloc(res->data, res->size + bytes);

    if (!res->data) {
      InternetCloseHandle(request);
      InternetCloseHandle(connection);
      res->error = "out of memory";
      return false;
    }

    if (InternetReadFile(request, res->data + res->size, bytes, &bytes)) {
      res->size += bytes;
    } else {
      free(res->data);
      InternetCloseHandle(request);
      InternetCloseHandle(connection);
      res->error = "system error while reading response";
      return false;
    }
  }

  InternetCloseHandle(request);
  InternetCloseHandle(connection);
  return true;
}

#elif defined(__ANDROID__)
#include <jni.h>

static JavaVM* jvm;

// LÖVR calls this before loading the plugin
jint JNI_OnLoad(JavaVM* vm, void* reserved) {
  jvm = vm;
  return 0;
}

static void http_init(void) {
  //
}

static void http_destroy(void) {
  //
}

static bool handleException(JNIEnv* jni, http_response_t* response, const char* message) {
  if ((*jni)->ExceptionCheck(jni)) {
    (*jni)->ExceptionClear(jni);
    response->error = message;
    return true;
  }
  return false;
}

static bool http_request(http_request_t* request, http_response_t* response) {
  if (!jvm) {
    response->error = "Java VM not available";
    return false;
  }

  JNIEnv* jni;
  if ((*jvm)->GetEnv(jvm, (void**) &jni, JNI_VERSION_1_6) == JNI_EDETACHED) {
    response->error = "Java VM not attached to this thread ;_;";
    return false;
  }

  // URL jurl = new URL(request->url);
  jclass jURL = (*jni)->FindClass(jni, "java/net/URL");
  jmethodID jURL_init = (*jni)->GetMethodID(jni, jURL, "<init>", "(Ljava/lang/String;)V");
  jstring jurlstring = (*jni)->NewStringUTF(jni, request->url);
  jobject jurl = (*jni)->NewObject(jni, jURL, jURL_init, jurlstring);
  if (handleException(jni, response, "invalid url")) return false;
  (*jni)->DeleteLocalRef(jni, jurlstring);

  // HttpURLConnection jconnection = (HttpURLConnection) jurl.openConnection();
  jmethodID jURL_openConnection = (*jni)->GetMethodID(jni, jURL, "openConnection", "()Ljava/net/URLConnection;");
  jobject jconnection = (*jni)->CallObjectMethod(jni, jurl, jURL_openConnection);
  if (handleException(jni, response, "connection failure")) return false;
  (*jni)->DeleteLocalRef(jni, jurl);
  (*jni)->DeleteLocalRef(jni, jURL);

  // jconnection.setRequestMethod(method);
  jclass jHttpURLConnection = (*jni)->FindClass(jni, "java/net/HttpURLConnection");
  jmethodID jHttpURLConnection_setRequestMethod = (*jni)->GetMethodID(jni, jHttpURLConnection, "setRequestMethod", "(Ljava/lang/String;)V");
  const char* method = request->method ? request->method : (request->data ? "POST" : "GET");
  jstring jmethod = (*jni)->NewStringUTF(jni, method);
  (*jni)->CallVoidMethod(jni, jconnection, jHttpURLConnection_setRequestMethod, jmethod);
  if (handleException(jni, response, "invalid request method")) return false;
  (*jni)->DeleteLocalRef(jni, jmethod);

  // jconnection.setRequestProperty(headerName, headerValue);
  jmethodID jURLConnection_setRequestProperty = (*jni)->GetMethodID(jni, jHttpURLConnection, "setRequestProperty", "(Ljava/lang/String;Ljava/lang/String;)V");
  for (uint32_t i = 0; i < request->headerCount; i++) {
    jstring jname = (*jni)->NewStringUTF(jni, request->headers[2 * i + 0]);
    jstring jvalue = (*jni)->NewStringUTF(jni, request->headers[2 * i + 1]);
    (*jni)->CallVoidMethod(jni, jconnection, jURLConnection_setRequestProperty, jname, jvalue);
    (*jni)->DeleteLocalRef(jni, jname);
    (*jni)->DeleteLocalRef(jni, jvalue);
  }

  if (request->data) {
    // jconnection.setDoOutput(true);
    jmethodID jURLConnection_setDoOutput = (*jni)->GetMethodID(jni, jHttpURLConnection, "setDoOutput", "(Z)V");
    (*jni)->CallVoidMethod(jni, jconnection, jURLConnection_setDoOutput, true);

    // OutputStream joutput = jconnection.getOutputStream();
    jmethodID jURLConnection_getOutputStream = (*jni)->GetMethodID(jni, jHttpURLConnection, "getOutputStream", "()Ljava/io/OutputStream;");
    jobject joutput = (*jni)->CallObjectMethod(jni, jconnection, jURLConnection_getOutputStream);
    if (handleException(jni, response, "failed to write request data")) return false;

    jbyteArray jarray = (*jni)->NewByteArray(jni, request->size);
    if (handleException(jni, response, "out of memory")) return false;

    // joutput.write(request->data);
    jbyte* bytes = (*jni)->GetByteArrayElements(jni, jarray, NULL);
    memcpy(bytes, request->data, request->size);
    (*jni)->ReleaseByteArrayElements(jni, jarray, bytes, 0);
    jclass jOutputStream = (*jni)->FindClass(jni, "java/io/OutputStream");
    jmethodID jOutputStream_write = (*jni)->GetMethodID(jni, jOutputStream, "write", "([B)V");
    (*jni)->CallVoidMethod(jni, joutput, jOutputStream_write, jarray);
    if (handleException(jni, response, "failed to write request data")) return false;
    (*jni)->DeleteLocalRef(jni, jarray);
    (*jni)->DeleteLocalRef(jni, joutput);
    (*jni)->DeleteLocalRef(jni, jOutputStream);
  }

  // jconnection.connect();
  jmethodID jURLConnection_connect = (*jni)->GetMethodID(jni, jHttpURLConnection, "connect", "()V");
  (*jni)->CallVoidMethod(jni, jconnection, jURLConnection_connect);
  if (handleException(jni, response, "connection failure")) return false;

  // response->status = jconnection.getResponseCode();
  jmethodID jHttpURLConnection_getResponseCode = (*jni)->GetMethodID(jni, jHttpURLConnection, "getResponseCode", "()I");
  response->status = (*jni)->CallIntMethod(jni, jconnection, jHttpURLConnection_getResponseCode);
  if (handleException(jni, response, "connection failure")) return false;

  jmethodID jHttpURLConnection_getHeaderFieldKey = (*jni)->GetMethodID(jni, jHttpURLConnection, "getHeaderFieldKey", "(I)Ljava/lang/String;");
  jmethodID jHttpURLConnection_getHeaderField = (*jni)->GetMethodID(jni, jHttpURLConnection, "getHeaderField", "(I)Ljava/lang/String;");

  jint headerIndex = 0;

  for (;;) {
    jstring jname = (*jni)->CallObjectMethod(jni, jconnection, jHttpURLConnection_getHeaderFieldKey, headerIndex);
    jstring jvalue = (*jni)->CallObjectMethod(jni, jconnection, jHttpURLConnection_getHeaderField, headerIndex);

    if (!jvalue) {
      break;
    }

    if (!jname) {
      headerIndex++;
      continue;
    }

    size_t nameLength = (*jni)->GetStringUTFLength(jni, jname);
    const char* name = (*jni)->GetStringUTFChars(jni, jname, NULL);

    size_t valueLength = (*jni)->GetStringUTFLength(jni, jvalue);
    const char* value = (*jni)->GetStringUTFChars(jni, jvalue, NULL);

    // TODO name/value use Java's weird "modified UTF" encoding.  It's close to utf8 but not quite.
    response->header_cb(response->userdata, name, nameLength, value, valueLength);

    (*jni)->ReleaseStringUTFChars(jni, jname, name);
    (*jni)->ReleaseStringUTFChars(jni, jvalue, value);
    (*jni)->DeleteLocalRef(jni, jname);
    (*jni)->DeleteLocalRef(jni, jvalue);
    headerIndex++;
  }

  // InputStream jinput = jconnection.getInputStream(); (or getErrorStream)
  jmethodID jURLConnection_getInputStream = (*jni)->GetMethodID(jni, jHttpURLConnection, "getInputStream", "()Ljava/io/InputStream;");
  jmethodID jURLConnection_getErrorStream = (*jni)->GetMethodID(jni, jHttpURLConnection, "getErrorStream", "()Ljava/io/InputStream;");

  jobject jinput;
  if (response->status >= 400) {
    jinput = (*jni)->CallObjectMethod(jni, jconnection, jURLConnection_getErrorStream);
  } else {
    jinput = (*jni)->CallObjectMethod(jni, jconnection, jURLConnection_getInputStream);
  }

  if (handleException(jni, response, "failed to read response data")) return false;

  jclass jInputStream = (*jni)->FindClass(jni, "java/io/InputStream");
  jmethodID jInputStream_read = (*jni)->GetMethodID(jni, jInputStream, "read", "([B)I");

  response->data = NULL;
  response->size = 0;

  jbyteArray jbuffer = (*jni)->NewByteArray(jni, 16384);
  if (handleException(jni, response, "out of memory")) return false;

  for (;;) {
    // int bytesRead = jinput.read(buffer);
    jint bytesRead = (*jni)->CallIntMethod(jni, jinput, jInputStream_read, jbuffer);
    if (handleException(jni, response, "failed to read response data")) return false;

    if (bytesRead == -1) {
      break;
    }

    response->data = realloc(response->data, response->size + bytesRead);

    if (!response->data) {
      response->error = "out of memory";
      return false;
    }

    (*jni)->GetByteArrayRegion(jni, jbuffer, 0, bytesRead, (jbyte*) response->data + response->size);
    response->size += bytesRead;
  }

  (*jni)->DeleteLocalRef(jni, jbuffer);
  (*jni)->DeleteLocalRef(jni, jinput);
  (*jni)->DeleteLocalRef(jni, jInputStream);

  // jconnection.disconnect();
  jmethodID jURLConnection_disconnect = (*jni)->GetMethodID(jni, jHttpURLConnection, "disconnect", "()V");
  (*jni)->CallVoidMethod(jni, jconnection, jURLConnection_disconnect);
  (*jni)->DeleteLocalRef(jni, jHttpURLConnection);
  (*jni)->DeleteLocalRef(jni, jconnection);

  return true;
}

#elif defined(__linux__)
#include <curl/curl.h>
#include <dlfcn.h>

typedef CURLcode fn_global_init(long flags);
typedef void fn_global_cleanup(void);
typedef CURL* fn_easy_init(void);
typedef CURLcode fn_easy_setopt(CURL *curl, CURLoption option, ...);
typedef CURLcode fn_easy_perform(CURL *curl);
typedef void fn_easy_cleanup(CURL* curl);
typedef CURLcode fn_easy_getinfo(CURL* curl, CURLINFO info, ...);
typedef const char* fn_easy_strerror(CURLcode error);
typedef struct curl_slist *fn_slist_append(struct curl_slist *list, const char *string);
typedef void fn_slist_free_all(struct curl_slist *list);

#define FN_DECLARE(f) fn_##f* f;
#define FN_LOAD(f) curl.f = (fn_##f*) dlsym(library, "curl_"#f);
#define FN_FOREACH(X)\
  X(global_init)\
  X(global_cleanup)\
  X(easy_init)\
  X(easy_setopt)\
  X(easy_perform)\
  X(easy_cleanup)\
  X(easy_getinfo)\
  X(easy_strerror)\
  X(slist_append)\
  X(slist_free_all)

static struct {
  FN_FOREACH(FN_DECLARE)
} curl;

static void* library;

static void http_init(void) {
  library = dlopen("libcurl.so", RTLD_LAZY);

  if (library) {
    FN_FOREACH(FN_LOAD)
    if (curl.global_init(CURL_GLOBAL_DEFAULT)) {
      dlclose(library);
      library = NULL;
    }
  }
}

static void http_destroy(void) {
  if (library) {
    curl.global_cleanup();
    dlclose(library);
  }
}

static size_t writer(void* buffer, size_t size, size_t count, void* userdata) {
  http_response_t* response = userdata;
  response->data = realloc(response->data, response->size + size * count);
  if (!response->data) {
    response->error = "out of memory";
    return 0;
  }
  memcpy(response->data + response->size, buffer, size * count);
  response->size += size * count;
  return size * count;
}

// would rather use curl_easy_nextheader, but it's too new right now
static size_t onHeader(char* buffer, size_t size, size_t count, void* userdata) {
  http_response_t* response = userdata;
  char* colon = memchr(buffer, ':', size * count);
  if (colon) {
    char* name = buffer;
    char* value = colon + 1;
    size_t nameLength = colon - buffer;
    size_t valueLength = size * count - (nameLength + 1);
    while (valueLength > 0 && (*value == ' ' || *value == '\t')) value++, valueLength--;
    while (valueLength > 0 && (value[valueLength - 1] == '\n' || value[valueLength - 1] == '\r')) valueLength--;
    response->header_cb(response->userdata, name, nameLength, value, valueLength);
  }
  return size * count;
}

static bool http_request(http_request_t* request, http_response_t* response) {
  if (!library) return response->error = "curl unavailable", false;

  CURL* handle = curl.easy_init();
  if (!handle) return response->error = "curl unavailable", false;

  curl.easy_setopt(handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
  curl.easy_setopt(handle, CURLOPT_URL, request->url);

  if (request->method) {
    curl.easy_setopt(handle, CURLOPT_CUSTOMREQUEST, request->method);
    if (!strcmp(request->method, "HEAD")) curl.easy_setopt(handle, CURLOPT_NOBODY, 1);
  }

  if (request->data && (!request->method || (strcmp(request->method, "GET") && strcmp(request->method, "HEAD")))) {
    curl.easy_setopt(handle, CURLOPT_POSTFIELDS, request->data);
    curl.easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) request->size);
  }

  struct curl_slist* headers = NULL;
  if (request->headerCount > 0) {
    char* header = NULL;
    size_t capacity = 0;
    for (uint32_t i = 0; i < request->headerCount; i++) {
      const char* name = request->headers[2 * i + 0];
      const char* value = request->headers[2 * i + 1];
      const char* format = "%s: %s";
      int length = snprintf(NULL, 0, format, name, value);
      if (length + 1 > capacity) {
        capacity = length + 1;
        header = realloc(header, capacity);
        if (!header) {
          response->error = "out of memory";
          return false;
        }
      }
      sprintf(header, format, name, value);
      headers = curl.slist_append(headers, header);
    }
    curl.easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    free(header);
  }

  curl.easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);

  response->size = 0;
  response->data = NULL;
  curl.easy_setopt(handle, CURLOPT_WRITEDATA, response);
  curl.easy_setopt(handle, CURLOPT_WRITEFUNCTION, writer);

  curl.easy_setopt(handle, CURLOPT_HEADERDATA, response);
  curl.easy_setopt(handle, CURLOPT_HEADERFUNCTION, onHeader);

  CURLcode error = curl.easy_perform(handle);

  if (error != CURLE_OK) {
    response->error = curl.easy_strerror(error);
    return false;
  }

  long status;
  curl.easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
  response->status = status;

  curl.easy_cleanup(handle);
  curl.slist_free_all(headers);
  return true;
}

#elif defined(__APPLE__)
#include <objc/objc-runtime.h>
#include <dispatch/dispatch.h>
#define cls(T) ((id) objc_getClass(#T))
#define msg(ret, obj, fn) ((ret(*)(id, SEL)) objc_msgSend)(obj, sel_getUid(fn))
#define msg1(ret, obj, fn, T1, A1) ((ret(*)(id, SEL, T1)) objc_msgSend)(obj, sel_getUid(fn), A1)
#define msg2(ret, obj, fn, T1, A1, T2, A2) ((ret(*)(id, SEL, T1, T2)) objc_msgSend)(obj, sel_getUid(fn), A1, A2)
#define msg3(ret, obj, fn, T1, A1, T2, A2, T3, A3) ((ret(*)(id, SEL, T1, T2, T3)) objc_msgSend)(obj, sel_getUid(fn), A1, A2, A3)

typedef void (^CompletionHandler)(id data, id response, id error);

static void http_init(void) {
  //
}

static void http_destroy(void) {
  //
}

static bool http_request(http_request_t* request, http_response_t* response) {
  id NSString = cls(NSString);
  id urlNS = msg1(id, NSString, "stringWithUTF8String:", const char*, request->url);
  id url = msg1(id, cls(NSURL), "URLWithString:", id, urlNS);
  id req = msg1(id, cls(NSMutableURLRequest), "requestWithURL:", id, url);

  // Method
  const char* method = request->method ? request->method : (request->data ? "POST" : "GET");
  id methodNS = msg1(id, NSString, "stringWithUTF8String:", const char*, method);
  msg1(void, req, "setHTTPMethod:", id, methodNS);

  // Body
  if (request->data && strcmp(method, "GET") && strcmp(method, "HEAD")) {
    id body = msg3(id, cls(NSData), "dataWithBytesNoCopy:length:freeWhenDone:", void*, (void*) request->data, unsigned long, (unsigned long) request->size, BOOL, NO);
    msg1(void, req, "setHTTPBody:", id, body);
  }

  // Headers
  for (uint32_t i = 0; i < request->headerCount; i++) {
    id key = msg1(id, NSString, "stringWithUTF8String:", const char*, request->headers[2 * i + 0]);
    id val = msg1(id, NSString, "stringWithUTF8String:", const char*, request->headers[2 * i + 1]);
    msg2(void, req, "setValue:forHTTPHeaderField:", id, val, id, key);
  }

  __block id data = nil;
  __block id res = nil;
  __block id error = nil;

  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

  CompletionHandler onComplete = ^(id d, id r, id e) {
    data = d;
    res = r;
    error = e;
    dispatch_semaphore_signal(semaphore);
  };

  // Task
  id session = msg(id, cls(NSURLSession), "sharedSession");
  id task = msg2(id, session, "dataTaskWithRequest:completionHandler:", id, req, CompletionHandler, onComplete);

  msg(void, task, "resume");

  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

  if (data) {
    response->size = msg(unsigned long, data, "length");
    response->data = malloc(response->size);
    if (!response->data) {
      response->error = "out of memory";
      return false;
    }
    msg2(void, data, "getBytes:length:", void*, response->data, unsigned long, response->size);
  }

  if (res) {
    response->status = msg(long, res, "statusCode");

    id headers = msg(id, res, "allHeaderFields");
    id enumerator = msg(id, headers, "keyEnumerator");

    for (;;) {
      id keyNS = msg(id, enumerator, "nextObject");

      if (!keyNS) break;

      id valNS = msg1(id, headers, "valueForKey:", id, keyNS);

      const char* key = msg(const char*, keyNS, "UTF8String");
      const char* val = msg(const char*, valNS, "UTF8String");
      unsigned long keyLength = msg(unsigned long, keyNS, "length");
      unsigned long valLength = msg(unsigned long, valNS, "length");

      response->header_cb(response->userdata, key, keyLength, val, valLength);
    }
  }

  response->error = "unknown error"; // TODO
  return !error;
}

#else
#error "Unsupported HTTP platform"
#endif

// Lua API

#include <lua.h>
#include <lauxlib.h>

static bool isunreserved(char c) {
  switch (c) {
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g': case 'h': case 'i':
    case 'j': case 'k': case 'l': case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':
    case 's': case 't': case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I':
    case 'J': case 'K': case 'L': case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R':
    case 'S': case 'T': case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
    case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': case '0':
    case '-': case '_': case '.': case '~':
      return true;
    default:
      return false;
  }
}

static size_t urlencode(char* dst, const char* str, size_t len) {
  size_t res = 0;
  for (size_t i = 0; i < len; i++, str++) {
    if (isunreserved(*str)) {
      dst[res++] = *str;
    } else {
      dst[res++] = '%';
      dst[res++] = '0' + *str / 16;
      dst[res++] = '0' + *str % 16;
    }
  }
  return res;
}

static void addheader(void* userdata, const char* name, size_t nameLength, const char* value, size_t valueLength) {
  lua_State* L = userdata;
  lua_pushlstring(L, name, nameLength);
  lua_pushlstring(L, value, valueLength);
  lua_settable(L, 3);
}

static int l_http_request(lua_State* L) {
  http_request_t request = { 0 };

  request.url = luaL_checkstring(L, 1);

  if (!strstr(request.url, "://")) {
    lua_pushliteral(L, "http://");
    lua_pushvalue(L, 1);
    lua_concat(L, 2);
    lua_replace(L, 1);
    request.url = lua_tostring(L, 1);
  }

  char* data = NULL;
  size_t size = 0;
  size_t capacity = 0;

  if (lua_istable(L, 2)) {
    lua_getfield(L, 2, "data");
    switch (lua_type(L, -1)) {
      case LUA_TNIL:
        break;
      case LUA_TSTRING:
        request.data = lua_tolstring(L, -1, &request.size);
        break;
      case LUA_TTABLE:
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
          if (lua_type(L, -2) == LUA_TSTRING && lua_isstring(L, -1)) {
            size_t keyLength, valLength;
            const char* key = lua_tolstring(L, -2, &keyLength);
            const char* val = lua_tolstring(L, -1, &valLength);
            size_t maxLength = 3 * keyLength + 1 + 3 * valLength + 1;
            if (size + maxLength > capacity) {
              capacity = size + maxLength;
              data = realloc(data, capacity);
              if (!data) return luaL_error(L, "Out of memory");
            }
            size += urlencode(data + size, key, keyLength);
            data[size++] = '=';
            size += urlencode(data + size, val, valLength);
            data[size++] = '&';
          }
          lua_pop(L, 1);
        }
        request.data = data;
        request.size = size - 1;
        break;
      case LUA_TLIGHTUSERDATA:
        lua_getfield(L, 2, "datasize");
        if (lua_type(L, -1) != LUA_TNUMBER) return luaL_error(L, "Expected numeric 'datasize' key");
        request.data = lua_touserdata(L, -2);
        request.size = lua_tointeger(L, -1);
        lua_pop(L, 1);
        break;
      default:
        return luaL_error(L, "Expected string, table, or lightuserdata for request data");
    }
    lua_pop(L, 1);

    lua_getglobal(L, "string");
    lua_getfield(L, -1, "upper");
    lua_getfield(L, 2, "method");
    if (lua_isstring(L, -1)) {
      lua_call(L, 1, 1);
      request.method = lua_tostring(L, -1);
      lua_pop(L, 2);
    } else {
      lua_pop(L, 3);
    }

    lua_getfield(L, 2, "headers");
    if (lua_istable(L, -1)) {
      lua_pushnil(L);
      while (lua_next(L, -2) != 0) {
        if (lua_type(L, -2) == LUA_TSTRING && lua_isstring(L, -1)) {
          request.headers = realloc(request.headers, (request.headerCount + 1) * 2 * sizeof(char*));
          if (!request.headers) return luaL_error(L, "Out of memory");
          request.headers[request.headerCount * 2 + 0] = lua_tostring(L, -2);
          request.headers[request.headerCount * 2 + 1] = lua_tostring(L, -1);
          request.headerCount++;
        }
        lua_pop(L, 1);
      }
    }
    lua_pop(L, 1);
  }

  http_response_t response = {
    .header_cb = addheader,
    .userdata = L
  };

  lua_settop(L, 2);
  lua_newtable(L);
  bool success = http_request(&request, &response);
  free(request.headers);
  free(data);

  if (!success) {
    lua_pushnil(L);
    lua_pushstring(L, response.error);
    return 2;
  }

  lua_pushinteger(L, response.status);
  lua_pushlstring(L, response.data, response.size);
  lua_pushvalue(L, -3);
  free(response.data);
  return 3;
}

int l_http_destroy(lua_State* L) {
  http_destroy();
  return 0;
}

int luaopen_http(lua_State* L) {
  http_init();

  lua_newtable(L);
  lua_pushcfunction(L, l_http_request);
  lua_setfield(L, -2, "request");

  lua_newuserdata(L, sizeof(void*));
  lua_createtable(L, 0, 1);
  lua_pushcfunction(L, l_http_destroy);
  lua_setfield(L, -2, "__gc");
  lua_setmetatable(L, -2);
  lua_setfield(L, -2, "");
  return 1;
}
