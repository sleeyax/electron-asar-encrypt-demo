# Encrypt source code for Electron application

## Why does this repository exist?

As we all know, [Electron](https://electronjs.org) officially does not provide a way to protect the source code. Packaging an Electron application, to put it bluntly, is [to copy the source to a fixed place](http://electronjs.org/docs/tutorial/application-distribution), such as `resources/app`. When running an Electron application, Electron treats this directory as a Node.js project to run the JS code in it. Although Electron recognizes the code package in ASAR format, that is, it can package all the source code into a `app.asar` file and put `resources` it in the directory. Electron regards it `app.asar` as a folder and runs the code inside, but the files in the ASAR package are not encrypted. The files are spliced ​​into one file and the file header information is added. It is easy to extract all the source code from the ASAR package using the official `asar` library , so the effect of encryption is not achieved, but it is only for beginners who want to access the source code. A little bit of a threshold, a little knowledgeable and completely stress-free.

So I was thinking about how to encrypt the ASAR package to prevent the commercial source code from being easily tampered with or inject some malicious code by some intentional people before distribution. Here is an idea to complete encryption without recompiling Electron.

## start running

``` bash
git clone https://github.com/toyobayashi/electron-asar-encrypt-demo.git
cd ./electron-asar-encrypt-demo
npm install # Copy electron release to the test directory 
npm start   # Compile and start the application 
npm test    # Compile and run the test
```

## encryption

Take AES-256-CBC as an example, first generate the key and save it in a local file, which is convenient for JS package script import and C++ include inline.

``` js
// This script will not be packaged into the client, for local development 
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

fs.writeFileSync(path.join(__dirname, 'src/key.txt'), Array.prototype.map.call(crypto.randomBytes(32), (v => ('0x' + ('0' + v.toString(16)).slice(-2)))))
```

This will `src` generate a key.txt file with the following contents:

```
0x87,0xdb,0x34,0xc6,0x73,0xab,0xae,0xad,0x4b,0xbe,0x38,0x4b,0xf5,0xd4,0xb5,0x43,0xfe,0x65,0x1c,0xf5,0x35,0xbb,0x4a,0x78,0x0a,0x78,0x61,0x65,0x99,0x2a,0xf1,0xbb
```

To encrypt when packaging, `asar` use `asar.createPackageWithOptions()` this API of the library:

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

The `transform` option , which is a function that returns a `ReadWriteStreamreadable` and writable stream to process the file, and returns to `undefined` not the file. In this step, all JS files are encrypted and put into ASAR package.

``` js
// This script will not be packaged into the client, for local development

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
    unpack: '*.node', // C++ modules do not pack 
    transform (filename) {
      if (path.extname(filename) === '.js') {
        // generate random 16-byte initialization vector IV 
        const iv = crypto.randomBytes(16)

        // Have you spelled the IV in the encrypted data 
        let append = false

        const cipher = crypto.createCipheriv(
          'aes-256-cbc',
          key,
          iv
        )
        cipher.setAutoPadding(true)
        cipher.setEncoding('base64')

        // Rewrite Readable.prototype.push to spell IV at the front of encrypted data
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

## main process decryption

Decryption is done when the client is running. Because the V8 engine cannot run the encrypted JS, it must be decrypted first and then thrown to V8 to run. There is a lot of emphasis here. The client code can be ravaged by anyone, so the key cannot be written clearly, nor can it be placed in the configuration file, so it can only be sunk into C++. Write a native module in C++ to achieve decryption, and this module cannot export the decryption method, otherwise it is meaningless. In addition, the key cannot be hard-coded as a string in the C++ source code, because the string can be found directly in the compiled binary file.

What? Isn't it useless without exporting? It's very simple. Hack the API of Node.js to ensure that it is OK if it is not available to the outside world, and then directly use the native module as the entry module, and then require the real entry JS in the native module. Here is the equivalent JS logic:
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
  // If the native module is not an entry, an error will be reported exit 
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
To use C++ to write the above code, there is a question, how to get JS `require` functions ?

Looking at the Node source code, you can see that calling  `require` is equivalent to calling `Module.prototype.require`, so as long as you can get the `module` object , you can also get the  `require` function. Unfortunately, NAPI does not expose the `module` object . Some people put forward a PR, but the official seems to consider some reasons (in line with the ES Module standard) and does not want to expose `module` it, only exposes the `exports` object , unlike the JS in the Node CommonJS module The code is wrapped in a layer of functions:

``` js
function (exports, require, module, __filename, __dirname) {
  // write your own code here 
}
```

If you read the Node.js documentation carefully, you can see that there is `global.process.mainModule` such say, the entry module can be obtained from the global, as long as you traverse the `children` array of modules and look down, if the `module.exports` comparison is not equal  `exports`, you can find the current The `module` object .

First encapsulate the method of running the script.
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

Then you can happily JS in C++.

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

Seeing this, you may ask why you still use C++ to write JS after working for a long time, isn't it `RunScript()` obvious ? As mentioned earlier, directly runScript needs to write JS into a string, which exists as it is in the compiled binary file, and the key will be leaked. Writing these logics in C++ can increase the difficulty of reverse.

To sum it up is this:

1. `main.node` (compiled) inside require `main.js` (encrypted)
2. `main.js` (encrypted) require other encrypted JS, create windows, etc.

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

## Rendering process decryption

Similar to the logic of the main process, the main process and the rendering process can be distinguished in C++ by using predefined macros. Compile another one for the rendering process `renderer.node`. The native module loaded by the rendering process must be `上下文感知模块`. The module written with NAPI is already context-aware, so there is no problem. If it is written with the V8 API, it will not work.

There is a limitation here, you cannot directly reference `<script>` tags load JS, because the in HTML `<script>` does not go `Module.prototype._compile`, so you can only call in the main process `browserWindow.webContents.executeJavaScript()` to first load the native module for each window, and then require other JS that may need to be decrypted document.

## limitations

* `nodeIntegration` option must be turned on . You can't use preload scripts either, because then the native module won't find its own moduleinstance and won't be able to use it `require`
* Only JS can be encrypted, other types of files cannot be encrypted, such as JSON, image resources, etc.
* All JS loading methods `Module.prototype._compile` that cannot load encrypted JS. For example <script>, script loading methods that rely on HTML tags are invalid, and Webpack dynamic import is `import()` invalid
* If there are a lot of JS files, the performance impact caused by decryption will be greater. The following will talk about how to reduce the JS that needs to be encrypted.
* It cannot be implemented in pure JS, and the key key and decryption method must be compiled in C++
* Can't make a paid application
* It cannot be considered absolutely safe. Decompilation of native modules still has the risk of key leakage and encryption methods being known, but compared with pure ASAR packaging, the threshold for cracking is slightly raised, and the source code is not so easy to access. If someone really wants to ravage your code, this approach may not be enough defense

The most effective way is to change the Electron source code and recompile Electron. However, the technical threshold of dynamic source code is high, recompiling Electron requires science, and the compilation is super slow.

## Reduce JS that needs to be encrypted

`node_modules` There is a lot of JS in it, and it does not need to be encrypted, so one can be extracted separately `node_modules.asar`. The JS in this is not encrypted. But this will bring more opportunities for reverse engineering, others can inject JS code they want to run in these NPM packages, which is risky.

How to make `require` find `node_modules.asar` the internal library? The answer is also Hack out Node's API.

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

In this `node_modules` way , it is OK to put it `node_modules.asar` into `resources` a folder and at the same level.`app.asar`

Remember to unpack `*.node` native modules.

## Summarize

Encryption is performed during packaging, decryption is performed at runtime, and the decryption logic is placed in C++, and it must be loaded first.

Last key, not in preloaded code `console.log`, don't forget to turn off `devTools` and `nodeIntegration`:

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
