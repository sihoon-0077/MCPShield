FROM --platform=linux/amd64 node@sha256:76789712cd1ae89a1225eac9077010d68987a423588042dac30446f502f1858c

# Trusted toolchain acquisition only. Candidate packages are never present in this build.
RUN apk upgrade --no-cache libcrypto3 libssl3
RUN node --input-type=module -e "import {writeFile} from 'node:fs/promises'; import {createHash} from 'node:crypto'; const r=await fetch('https://registry.npmjs.org/npm/-/npm-12.0.2.tgz',{redirect:'error',signal:AbortSignal.timeout(30000)}); if(!r.ok) throw Error('NPM_DOWNLOAD_FAILED'); const b=Buffer.from(await r.arrayBuffer()); if(b.length>20000000 || createHash('sha512').update(b).digest('base64')!=='uIXokLlBj6FpNUTQX1PmT5pz7BlIN9QlixX+zdaSNHsd0qUXsbDLr50xzY6Sw7cJVr0uzHKDOle0swmPW/p5Qw==') throw Error('NPM_INTEGRITY_FAILED'); await writeFile('/tmp/npm-toolchain.tgz',b);" \
 && npm install --global --ignore-scripts --audit=false --fund=false /tmp/npm-toolchain.tgz \
 && rm /tmp/npm-toolchain.tgz \
 && test "$(npm --version)" = '12.0.2'
COPY services/resolver/src/prepare-container.mjs services/resolver/src/closure-files.mjs /trusted/
RUN mkdir /work && chown 1000:1000 /work
LABEL io.mcpshield.runtime-builder="node-closure-v1" io.mcpshield.npm-version="12.0.2"
USER 1000:1000
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/node", "/trusted/prepare-container.mjs"]
