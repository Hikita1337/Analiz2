
const ivm = require('isolated-vm');
const fs = require('fs');

async function run() {
    const code = fs.readFileSync(process.argv[2], 'utf8');

    let isolate = new ivm.Isolate({ memoryLimit: 16 });
    let context = await isolate.createContext();

    let script;
    try {
        script = await isolate.compileScript(code);
        let result = await script.run(context, { timeout: 100 });
        console.log(JSON.stringify({ok: true, result: String(result)}));
    } catch (e) {
        console.log(JSON.stringify({ok: false, error: e.message}));
    }
}
run();
