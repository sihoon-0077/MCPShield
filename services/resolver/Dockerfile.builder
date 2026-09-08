FROM --platform=linux/amd64 node@sha256:76789712cd1ae89a1225eac9077010d68987a423588042dac30446f502f1858c

# Trusted toolchain acquisition only. Candidate packages are never present in this build.
RUN apk upgrade --no-cache libcrypto3 libssl3
RUN node --input-type=module -e "import {writeFile} from 'node:fs/promises'; import {createHash} from 'node:crypto'; const r=await fetch('https://registry.npmjs.org/npm/-/npm-12.0.2.tgz',{redirect:'error',signal:AbortSignal.timeout(30000)}); if(!r.ok) throw Error('NPM_DOWNLOAD_FAILED'); const b=Buffer.from(await r.arrayBuffer()); if(b.length>20000000 || createHash('sha512').update(b).digest('base64')!=='uIXokLlBj6FpNUTQX1PmT5pz7BlIN9QlixX+zdaSNHsd0qUXsbDLr50xzY6Sw7cJVr0uzHKDOle0swmPW/p5Qw==') throw Error('NPM_INTEGRITY_FAILED'); await writeFile('/tmp/npm-toolchain.tgz',b);" \
 && npm install --global --ignore-scripts --audit=false --fund=false /tmp/npm-toolchain.tgz \
 && rm /tmp/npm-toolchain.tgz \
 && test "$(npm --version)" = '12.0.2'
# npm 12.0.2 itself bundles older vulnerable transitive packages. Replace only
# these verified official archives; native tar does not execute lifecycle scripts
# or resolve/install development dependencies. Their dependency ranges are unchanged.
RUN set -eu; node --input-type=module -e "import {writeFile} from 'node:fs/promises'; import {createHash} from 'node:crypto'; const patches=[['brace-expansion','5.0.9','ScQ4IuvIEF1TMlP7Zt+vjJ//9zlPb2SDcxWxM3bk8s6t6GGdJ7KO1dCcTidOPJKePW30LE/2cT7wCyPho9/Wxg=='],['ip-address','10.3.1','1e9d3kb97NHJTIJDZW9rKqW2h6+dFa50Dy0fpPSMQp2ADje5gvKsXmdiK6dwY5t76TaTt5+P5N1Y/LoToIxP6g=='],['tar','7.5.22','MFO/QzvtAOmJbkhOaCTvbGcFN9L9b+JunIsDwaKljSOdcLMea3NJ1k9Usz/rjdfSXTq4dfzfeS7W4p4YOAAHeA==']]; for(const [name,version,expected] of patches){const r=await fetch('https://registry.npmjs.org/'+name+'/-/'+name+'-'+version+'.tgz',{redirect:'error',signal:AbortSignal.timeout(30000)}); if(!r.ok) throw Error('PATCH_DOWNLOAD_FAILED'); const chunks=[];let size=0;for await(const chunk of r.body){size+=chunk.length;if(size>5000000)throw Error('PATCH_SIZE_LIMIT');chunks.push(chunk)} const b=Buffer.concat(chunks);if(createHash('sha512').update(b).digest('base64')!==expected)throw Error('PATCH_INTEGRITY_FAILED');await writeFile('/tmp/toolchain-'+name+'.tgz',b)}"; \
 for pkg in brace-expansion ip-address tar; do \
   rm -r "/usr/local/lib/node_modules/npm/node_modules/$pkg"; \
   mkdir "/usr/local/lib/node_modules/npm/node_modules/$pkg"; \
   tar -xzf "/tmp/toolchain-$pkg.tgz" -C "/usr/local/lib/node_modules/npm/node_modules/$pkg" --strip-components=1; \
   rm "/tmp/toolchain-$pkg.tgz"; \
 done; \
 node --input-type=module -e "import {readFile} from 'node:fs/promises';for(const [name,version]of [['brace-expansion','5.0.9'],['ip-address','10.3.1'],['tar','7.5.22']]){if(JSON.parse(await readFile('/usr/local/lib/node_modules/npm/node_modules/'+name+'/package.json')).version!==version)throw Error('PATCH_VERSION_MISMATCH')}"; \
 test "$(npm --version)" = '12.0.2'
COPY services/resolver/src/prepare-container.mjs services/resolver/src/closure-files.mjs /trusted/
RUN mkdir /work && chown 1000:1000 /work
LABEL io.mcpshield.runtime-builder="node-closure-v1" io.mcpshield.npm-version="12.0.2"
LABEL io.mcpshield.npm-patches="brace-expansion@5.0.9,ip-address@10.3.1,tar@7.5.22"
USER 1000:1000
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/node", "/trusted/prepare-container.mjs"]
