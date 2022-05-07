# Encrypting source code for Electron applications

## Why does this repository exist?

As we all know, [Electron](https://electronjs.org) does not officially provide a way to protect the source code. To package an Electron application, you simply [copy the source code to a fixed location](http://electronjs.org/docs/tutorial/application-distribution), such as the `resources/app` directory on Windows/Linux. When running an Electron application, Electron treats this directory as a Node.js project to run the JS code in. However, the files in the ASAR package are not encrypted, they are just stitched together into one file with header information, and it is easy to extract all the source code from the ASAR package using the official `asar` library, so the effect of encryption is not achieved.

So I was thinking about how to encrypt the ASAR package to prevent the commercial source code from being easily tampered or injected with some malicious code by some people who want to distribute it again. Here is a way to do it without recompiling Electron.

## Start running

``` bash
git clone https://github.com/toyobayashi/electron-asar-encrypt-demo.git
cd ./electron-asar-encrypt-demo
npm install # Copy electron release to the test directory 
npm start   # Compile and start the application 
npm test    # Compile and run the test
```

## Encryption

As an example, a key is encrypted with AES-256-CBC and stored in a local file for easy import into JS package scripts and inline with C++ include.

``` js
// This script is not packaged into the client and is used for local development
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

fs.writeFileSync(path.join(__dirname, 'src/key.txt'), Array.prototype.map.call(crypto.randomBytes(32), (v => ('0x' + ('0' + v.toString(16)).slice(-2)))))
```

This generates a `key.txt` file in `src`, which looks like this:

```
0x87,0xdb,0x34,0xc6,0x73,0xab,0xae,0xad,0x4b,0xbe,0x38,0x4b,0xf5,0xd4,0xb5,0x43,0xfe,0x65,0x1c,0xf5,0x35,0xbb,0x4a,0x78,0x0a,0x78,0x61,0x65,0x99,0x2a,0xf1,0xbb
```

Encryption is done when packaging, using the `asar.createPackageWithOptions()` API of the `asar` library:

``` ts
/// <reference types="node" />

declare namespace asar {
  // ...
  export function createPackageWithOptions(
    src: string,
    dest: string,
    options: {
      // ...
      transform?: (filePath: string) => NodeJS.ReadWriteStream | void;
    }
  ): Promise<void>
}

export = asar;
```

Pass the transform option in the third argument, which is a function that returns a `ReadWriteStream` to process the file, or undefined if it does not process the file. This step encrypts all JS files and inserts them into the ASAR package.

``` js
// This script is not packaged into the client and is used for local development

const crypto = require('crypto')
const path = require('path')
const fs = require('fs')
const asar = require('asar')

// Read the key and make a Buffer 
const key = Buffer.from(fs.readFileSync(path.join(__dirname, 'src/key.txt'), 'utf8').trim().split(',').map(v => Number(v.trim())))

asar.createPackageWithOptions(
  path.join(__dirname, './app'),
  path.join(__dirname, './test/resources/app.asar'),
  {
    unpack: '*.node', // do not pack C++ modules 
    transform (filename) {
      if (path.extname(filename) === '.js') {
        // generate a random 16-byte initialization vector IV
        const iv = crypto.randomBytes(16)

        // whether we have already put the IV at the start of the encrypted data (see below)
        let append = false

        const cipher = crypto.createCipheriv(
          'aes-256-cbc',
          key,
          iv
        )
        cipher.setAutoPadding(true)
        cipher.setEncoding('base64')

        // rewrite `Readable.prototype.push` to put the IV at the start of the encrypted data
        const _p = cipher.push
        cipher.push = function (chunk, enc) {
          if (!append && chunk != null) {
            append = true
            return _p.call(this, Buffer.concat([iv, chunk]), enc)
          } else {
            return _p.call(this, chunk, enc)
          }
        }
        return cipher
      }
    }
  }
)
```

## Main process decryption
Decryption is done client-side because the V8 engine can't run the encrypted JS, so it must be decrypted before being thrown to V8 to run. The client-side code can be accessed by anyone, so the key cannot be written explicitly or placed in a configuration file, so it has to be put into C++. Write a native module in C++ to implement decryption, and this module can not export decryption methods, otherwise it is meaningless. Also the key cannot be written hard coded in C++ source code as a string, because a string can be easily found in a compiled binary file.

What? Can't we use it without exporting it? It's easy to Hack the Node.js API to make sure it's not available externally, then use the native module as the entry module and require the real entry JS in the native module.
``` js
// Write the following logic in C++, so that the key can be compiled into the dynamic library 
// Only by decompiling the dynamic library can it be analyzed

// disable debugging 
for (let i = 0; i < process.argv.length; i++) {
  if (process.argv[i].startsWith('--inspect') ||
      process.argv[i].startsWith('--remote-debugging-port')) {
    throw new Error('Not allow debugging this program.')
  }
}

const { app, dialog } = require('electron')

const moduleParent = module.parent;
if (module !== process.mainModule || (moduleParent !== Module && moduleParent !== undefined && moduleParent !== null)) {
  // If the native module is not an entry, an error will be reported and exit 
  dialog.showErrorBox('Error', 'This program has been changed by others.')
  app.quit()
}

const Module = require('module')

function getKey () {
  // inline the key generated by the JS script here 
  // const unsigned char key[32] = { 
  // #include "key.txt" 
  // }; 
  return KEY
}

function decrypt (body) { // body is Buffer 
  const iv = body.slice(0, 16) // first 16 bytes are IV 
  const data = body.slice(16) // after 16 bytes is encrypted code

  // It is better to use the native library for decryption, the Node API is at risk of being intercepted

  // const clearEncoding = 'utf8' // output is string 
  // const cipherEncoding = 'binary' // input is binary 
  // const chunks = [] // string to save chunks 
  // const decipher = require(' crypto').createDecipheriv( 
  // 'aes-256-cbc', 
  // getKey(), 
  // iv 
  // ) 
  // decipher.setAutoPadding(true) 
  // chunks.push(decipher.update(data, cipherEncoding, clearEncoding)) 
  // chunks.push(decipher.final(clearEncoding)) 
  // const code = chunks.join('') 
  // return code

  // [native code]
}

const oldCompile = Module.prototype._compile
// Rewrite Module.prototype . _compile 
// I won't write more about the reason, just look at the source code of Node and you will know 
Object.defineProperty(Module.prototype, '_compile', {
  enumerable: true,
  value: function (content, filename) {
    if (filename.indexOf('app.asar') !== -1) {
      // If this JS is in app.asar, decrypt it first 
      return oldCompile.call(this, decrypt(Buffer.from(content, 'base64')), filename)
    }
    return oldCompile.call(this, content, filename)
  }
})

try {
  // The main process creates the window here, if necessary, pass the key to JS, it is best not to pass
  require('./main.js')(getKey()) 
} catch (err) {
  // prevent Electron does not exit 
  dialog.showErrorBox('Error', err.stack)
  app.quit()
}
```
To write the above code in C++, there is a problem: How do I get the JS `require` function in C++?

If you look at the Node source code, you can see that calling require is equivalent to calling `Module.prototype.require`, so if you can get the module object, you can also get the `require` function. Unfortunately, NAPI does not expose the module object in the module initialization callback, someone mentioned PR but it seems that for some reason (aligning with the ES Module standard) the Node.js developers do not want to expose the module, only the exports object, unlike the Node CommonJS module where the JS code is wrapped in a layer of functions.

``` js
function (exports, require, module, __filename, __dirname) {
  // write your own code here 
}
```

If you look through the Node.js documentation, you can see in the process section that there is such a thing as `global.process.mainModule`, which means that the entry module can be obtained from the global, and you can find the module object of the current native module by traversing the children array of the module and comparing `module.exports`, which is not equal to `exports`. you can find the module object of the current native module.

First, let's encapsulate the method of running the script.
``` cpp
#include <string>
#include "napi.h"

// First encapsulate the script running method 
Napi::Value RunScript(Napi::Env& env, const Napi::String& script) {
  napi_value res;
  NAPI_THROW_IF_FAILED(env, napi_run_script(env, script, &res), env.Undefined());
  return Napi::Value(env, res); // env.RunScript(script);
}

Napi::Value RunScript(Napi::Env& env, const std::string& script) {
  return RunScript(env, Napi::String::New(env, script)); // env.RunScript(script);
}

Napi::Value RunScript(Napi::Env& env, const char* script) {
  return RunScript(env, Napi::String::New(env, script)); // env.RunScript(script);
}
```

`node-addon-api` v3 and above can be used directly:

``` cpp
Napi::Value Napi::Env::RunScript(const char* utf8script);
Napi::Value Napi::Env::RunScript(const std::string& utf8script);
Napi::Value Napi::Env::RunScript(Napi::String script);
```

Then you can happily execute JS code in C++.

``` cpp
Napi::Value GetModuleObject(Napi::Env& env, const Napi::Object& main_module, const Napi::Object& exports) {
  std::string script = "(function (mainModule, exports) {\n"
    "function findModule(start, target) {\n"
    "  if (start.exports === target) {\n"
    "    return start;\n"
    "  }\n"
    "  for (var i = 0; i < start.children.length; i++) {\n"
    "    var res = findModule(start.children[i], target);\n"
    "    if (res) {\n"
    "      return res;\n"
    "    }\n"
    "  }\n"
    "  return null;\n"
    "}\n"
    "return findModule(mainModule, exports);\n"
    "});";
  Napi::Function find_function = RunScript(env, script).As<Napi::Function>();
  Napi::Value res = find_function({ main_module, exports });
  if (res.IsNull()) {
    Napi::Error::New(env, "Cannot find module object.").ThrowAsJavaScriptException();
  }
  return res;
}
Napi::Function MakeRequireFunction(Napi::Env& env, const Napi::Object& mod) {
  std::string script = "(function makeRequireFunction(mod) {\n"
      "const Module = mod.constructor;\n"

      "function validateString (value, name) { if (typeof value !== 'string') throw new TypeError('The \"' + name + '\" argument must be of type string. Received type ' + typeof value); }\n"

      "const require = function require(path) {\n"
      "  return mod.require(path);\n"
      "};\n"

      "function resolve(request, options) {\n"
        "validateString(request, 'request');\n"
        "return Module._resolveFilename(request, mod, false, options);\n"
      "}\n"

      "require.resolve = resolve;\n"

      "function paths(request) {\n"
        "validateString(request, 'request');\n"
        "return Module._resolveLookupPaths(request, mod);\n"
      "}\n"

      "resolve.paths = paths;\n"

      "require.main = process.mainModule;\n"

      "require.extensions = Module._extensions;\n"

      "require.cache = Module._cache;\n"

      "return require;\n"
    "});";

  Napi::Function make_require = RunScript(env, script).As<Napi::Function>();
  return make_require({ mod }).As<Napi::Function>();
}
```

``` cpp
#include <unordered_map>

struct AddonData {
  // Save Node module reference 
  // std::unordered_map<std::string, Napi::ObjectReference> modules; 
  // Save function reference
  std::unordered_map<std::string, Napi::FunctionReference> functions;
};

Napi::Value ModulePrototypeCompile(const Napi::CallbackInfo& info) {
  AddonData* addon_data = static_cast<AddonData*>(info.Data());
  Napi::Function old_compile = addon_data->functions["Module.prototype._compile"].Value();
  // It is recommended to use a C/C++ library for decryption // ...
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
#ifdef _TARGET_ELECTRON_RENDERER_
  // const mainModule = window.module
  Napi::Object main_module = env.Global().Get("module").As<Napi::Object>();
#else
  
  Napi::Object process = env.Global().Get("process").As<Napi::Object>();
  Napi::Array argv = process.Get("argv").As<Napi::Array>();
  for (uint32_t i = 0; i < argv.Length(); ++i) {
    std::string arg = argv.Get(i).As<Napi::String>().Utf8Value();
    if (arg.find("--inspect") == 0 ||
        arg.find("--remote-debugging-port") == 0) {
      Napi::Error::New(env, "Not allow debugging this program.")
        .ThrowAsJavaScriptException();
      return exports;
    }
  }
  // const mainModule = process.mainModule
  Napi::Object main_module = process.Get("mainModule").As<Napi::Object>();
#endif

  Napi::Object this_module = GetModuleObject(&env, main_module, exports).As<Napi::Object>();
  Napi::Function require = MakeRequireFunction(env, this_module);
  // const mainModule = process.mainModule
  Napi::Object main_module = env.Global().As<Napi::Object>().Get("process").As<Napi::Object>().Get("mainModule").As<Napi::Object>();
  // const electron = require('electron')
  Napi::Object electron = require({ Napi::String::New(env, "electron") }).As<Napi::Object>();
  // require('module')
  Napi::Object module_constructor = require({ Napi::String::New(env, "module") }).As<Napi::Object>();
  // module.parent
  Napi::Value module_parent = this_module.Get("parent");

  if (this_module != main_module ||
      (module_parent != module_constructor && module_parent != env.Undefined() && module_parent != env.Null())) {
    // The entry module is not the current native module and may be intercepted by the API to leak the key 
    // pop-up warning after exit
  }

  AddonData* addon_data = env.GetInstanceData<AddonData>();

  if (addon_data == nullptr) {
    addon_data = new AddonData();
    env.SetInstanceData(addon_data);
  }

  // require('crypto')
  // addon_data->modules["crypto"] = Napi::Persistent(require({ Napi::String::New(env, "crypto") }).As<Napi::Object>());

  Napi::Object module_prototype = module_constructor.Get("prototype").As<Napi::Object>();
  addon_data->functions["Module.prototype._compile"] = Napi::Persistent(module_prototype.Get("_compile").As<Napi::Function>());
  module_prototype["_compile"] = Napi::Function::New(env, ModulePrototypeCompile, "_compile", addon_data);

  try {
    require({ Napi::String::New(env, "./main.js") }).Call({ getKey() });
  } catch (const Napi::Error& e) {
    // Exit after the popup window 
    // ...
  }
  return exports;
}

// Don't use semicolon, NODE_API_MODULE is a macro 
NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
```

You may ask why you need to use C++ to write JS after all this time, isn't it obvious that you can `RunScript()`. As mentioned earlier, `RunScript()` directly requires JS to be written as a string, which exists in the compiled binary as is, and the key will be leaked, so using C++ to write the logic can increase the difficulty to reverse engineer.

To summarize, it looks like this:
1. `main.node` (compiled) inside requires `main.js` (encrypted)
2. `main.js` (encrypted) requires other encrypted JS, creates windows, etc.

Note that the entry must be main.node. If it is not, it is very likely that the attacker will hack the Node API in the JS before main.node is loaded, resulting in key leakage. For example, an entry file like this:

``` js
const crypto = require('crypto')

const old = crypto.createDecipheriv
crypto.createDecipheriv = function (...args) {
  console.log(...args) // key is output 
  return old.call(crypto, ...args)
}

const Module = require('module')

const oldCompile = Module.prototype._compile
      
Module.prototype._compile = function (content, filename) {
  console.log(content) // JS source code is output 
  return oldCompile.call(this, content, filename)
}

process.argv.length = 1

require('./main.node')
// or Module._load('./main.node', module, true)
```

## Render process decryption
Similar to the logic of the main process, you can use predefined macros in C++ to distinguish between the main process and the rendering process. The native module loaded by the rendering process must be context-aware, and the module written in NAPI is already context-aware, so there is no problem, but not if written in the V8 API.

There is a restriction that you can't load JS in HTML by directly referencing the `<script>` tag, because `<script>` in HTML doesn't go `Module.prototype._compile`, so you can only call `browserWindow.webContents.executeJavaScript()` in the main process to load the native module first for each window, and then require any other JS files that may need to be decrypted.

## Limitations

* `nodeIntegration` option must be turned on . You can't use preload scripts either, because then the native module won't find its own module instance and won't be able to use `require`.
* Only JS can be encrypted, not other types of files, such as JSON, image resources, etc.
* All JS load methods that do not take `Module.prototype._compile` will not load encrypted JS, e.g. script loading methods that rely on HTML `<script>` tags fail, and Webpack's dynamic `import()` fails.
* If there are a lot of JS files, the performance impact caused by decryption will be greater.
* You can't use a pure JS implementation, you have to compile the key and decryption methods in C++.
* Cannot be made into a paid application.
* It's not absolutely secure, decompiling the native module still risks the key being leaked and the encryption method being learned, it just raises the cracking threshold a little compared to just ASAR packaging, and the source code is not so easily accessible. If someone really wants to reverse your code, this method may not be enough defense.

The most effective way is to change the Electron source code and recompile Electron, but the technical threshold for moving the source code is high, recompiling Electron requires science and the compilation is super slow.

## Reduce JS that needs to be encrypted

There is a lot of JS inside node_modules and it doesn't need to be encrypted, so you can pull out a separate `node_modules.asar`, which has unencrypted JS. But this would give more opportunities to reverse engineers, and someone could inject the JS code they want to run in these NPM packages, which is risky.

How do you get `require` to find the libraries inside `node_modules.asar`? Again, the answer is to hack away at Node's API.

``` js
const path = require('path')
const Module = require('module')

const originalResolveLookupPaths = Module._resolveLookupPaths

Module._resolveLookupPaths = originalResolveLookupPaths.length === 2 ? function (request, parent) {
  // Node v12+
  const result = originalResolveLookupPaths.call(this, request, parent)

  if (!result) return result

  for (let i = 0; i < result.length; i++) {
    if (path.basename(result[i]) === 'node_modules') {
      result.splice(i + 1, 0, result[i] + '.asar')
      i++
    }
  }

  return result
} : function (request, parent, newReturn) {
  // Node v10-
  const result = originalResolveLookupPaths.call(this, request, parent, newReturn)

  const paths = newReturn ? result : result[1]
  for (let i = 0; i < paths.length; i++) {
    if (path.basename(paths[i]) === 'node_modules') {
      paths.splice(i + 1, 0, paths[i] + '.asar')
      i++
    }
  }

  return result
}
```

It's OK to make `node_modules` into `node_modules.asar` and put it in the resources folder at the same level as `app.asar`.

Be careful and remember to unpack `*.node` native modules.

## Summary

Do encryption at package time, decryption at runtime, decryption logic in C++, and must be the first to load.

The last key, don't `console.log` in the preloaded code, and don't forget to turn off devTools and turn on `nodeIntegration` in the production environment.

``` js
new BrowserWindow({
  // ...
  webPreferences: {
    nodeIntegration: true, // the rendering process should use require 
    contextIsolation: false, // Electron 12 starts with the default value of true, to turn off 
    devTools: false // Turn off the developer tools , because the developer tools can see the code of the rendering proc
  }
})
```
