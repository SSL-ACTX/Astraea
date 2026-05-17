const fs = require('fs');
const iterations = 10000;

console.log(`--- Astraea Benchmark: ${iterations} reads ---`);

const start = Date.now();
for (let i = 0; i < iterations; i++) {
    fs.readFileSync('astraea.toml');
}
const end = Date.now();

console.log(`Total time: ${end - start}ms`);
console.log(`Average time: ${(end - start) / iterations}ms`);
