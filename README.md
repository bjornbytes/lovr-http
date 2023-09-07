lovr-http
===

An HTTP(S) plugin for Lua.  lovr-http's design was inspired by
[lua-https](https://github.com/love2d/lua-https). Although the name is lovr-http, the library is
self-contained and doesn't rely on any parts of LÖVR, so it should work in any Lua program.  It was
just designed to be used as a LÖVR plugin.

Example
---

```lua
http = require 'http'

status, data = http.request('https://zombo.com')

print('welcome')
print(status)
print(data)
```

API
---

The module has one function:

```lua
status, data, headers = http.request(url, [options])
```

### Arguments

`url` is the URL to request.  It should start with the protocol (`http://` or `https://`).

`options` is optional, and is used for advanced request settings.

`options.method` is the HTTP method to use, also called the verb.  `GET` is used by default if
there's no data in the request, otherwise it defauls to `POST`.

`options.data` is the data to send to the server, also called the body.  It can be a few different
types:

- When `data` is nil, no request body will be sent (and `method` will default to `GET`).
- When `data` is a string, the string will be used directly as the request body.
- When `data` is a table, then pairs in the table will be URL encoded and concatenated together to
  form an `application/x-www-urlencoded` body.  For example, if data is `{ n = 10, k = 'v!' }`, then
  the request body will be something like `k=v%21&n=10`.  Keys can appear in any order.  Table pairs
  will only be used if the key is a string and the value is a string or number.
- When `data` is a lightuserdata, the data pointed to by the lightuserdata will be used as the
  request body.  Additionally, the `datasize` option should be an integer indicating how big the
  request body is, in bytes.

When `options.data` is set, the `Content-Type` request header will default to
`application/x-www-urlencoded` unless it's set to something else.

`options.headers` is a table of request headers to send to the server.  Pairs in the table will only
be used if the key is a string and the value is a string or number.

### Returns

If an error occurs, the function returns `nil, errormessage`.

Otherwise, 3 values are returned:

- `status` is an integer with the HTTP status code (200 is OK, 404 is Not Found, etc.).
- `data` is a string with the data sent by the server (HTML, JSON, binary, etc.).
- `headers` is a table of response headers.

Limitations
---

- `multipart/form-data` request bodies are not supported.
- Multi-line response headers are not parsed correctly on all platforms.
- There is no way to specify a request timeout, because not all platforms support it.
- There is currently no way to limit or restrict HTTP redirects.
- Adding credentials in the URL is not supported.  Use the `Authorization` request header instead.
- There are differences in behavior between platforms.  If you encounter any that are causing you
  problems, please open an issue.
- I don't even know what a proxy is but it's probably not going to work.

Compiling
---

The build system is CMake.  The CMake script doesn't have any logic to link against Lua yet, so it
will only build properly in LÖVR's `plugins` folder, where it will automatically use LÖVR's copy of
Lua.

Implementation
---

`lovr-http` uses system-provided HTTP libraries:

- Windows uses wininet.
- Linux uses curl (must be installed, but most systems have it).
- Android uses Java's HttpURLConnection via JNI.
- macOS uses NSURLSession.

The system's certificates are used for HTTPS.

License
---

MIT, see the [LICENSE](./LICENSE) file for details.
