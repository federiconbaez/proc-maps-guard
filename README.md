# proc-maps-guard

Audita el mapa de memoria de un proceso (`/proc/<pid>/maps`) en busca de código que no debería estar ahí: páginas escribibles y ejecutables, memoria anónima ejecutable, código mapeado desde un memfd o desde un archivo borrado, y W^X evadido mapeando dos veces el mismo archivo. Solo lee `maps`; nunca toca la memoria del proceso.

Audits a process's memory map (`/proc/<pid>/maps`) for code that should not be there: writable and executable pages, executable anonymous memory, code mapped from a memfd or from a deleted file, and W^X bypassed by mapping the same file twice. It only reads `maps`; it never touches the process's memory.

```
$ maps-guard --pid 4242 --allow-anon-exec v8-code --exec-prefix /usr/
critical write-exec line 32: 167936 bytes rwx [c9ca12a3000-c9ca12cc000 rwxp 00000000 00:00 0]
high memfd-exec line 40: code mapped from memfd 'payload' [...]
/proc/4242/maps: 212 mappings, 2 findings          # exit 1; 0 = clean, 2 = usage/read error
```

## Español

**Reglas**

| regla | severidad | dispara cuando |
|---|---|---|
| `write-exec` | crítica | un mapeo `w` y `x` a la vez |
| `aliased-write-exec` | crítica | el mismo archivo o memfd (dev+inode) mapeado **compartido** dos veces, uno escribible y otro ejecutable: W^X evadido por alias |
| `anon-exec` | alta | memoria anónima ejecutable (incluye heap y stack); no se repite si ya es `write-exec` |
| `memfd-exec` | alta | código mapeado desde `/memfd:` (nunca existió en disco) |
| `deleted-exec` | media | archivo ejecutable mapeado que fue borrado o reemplazado |
| `exec-outside-prefixes` | media | archivo ejecutable fuera de los prefijos configurados (opcional) |

`[vdso]` y `[vsyscall]` son ejecutables pero no cuentan como memoria anónima. Las regiones `[anon:<nombre>]` (nombradas con `prctl(PR_SET_VMA_ANON_NAME)`, como hacen algunos JIT) se pueden permitir por nombre con `--allow-anon-exec` o `--allow-write-exec`; una región sin nombre nunca queda permitida.

**Parser**: formato de proc(5) completo: direcciones de cualquier ancho, `p`/`s`, dispositivo `major:minor` en hex, rutas con espacios, sufijo ` (deleted)`, `[anon:…]`, `[anon_shmem:…]`, `[stack:tid]` y pseudo-rutas desconocidas. Los errores dicen línea, columna y motivo.

**Pruebas** (`cargo test`)

- Parser (5): todos los tipos de respaldo; 13 líneas malformadas, cada una con su columna exacta; el `/proc/self/maps` real ordenado y sin solapamientos; proptest de ida y vuelta `Display` → `parse` con rutas con espacios y memfd; texto arbitrario sin pánico.
- Reglas con fixtures (4): un proceso normal (x86-64, con libc, vdso y vsyscall) sin hallazgos incluso con `--exec-prefix /usr/`; una tabla sospechosa donde cada regla dispara en la línea exacta; listas permitidas y prefijos; orden de severidades.
- En vivo (5), mapeos reales creados por el propio test: el proceso de test arranca limpio; `mmap` RWX → `write-exec` con el rango correcto; `mprotect` a RX → `anon-exec`; nombrado con `PR_SET_VMA_ANON_NAME` y permitido por nombre; memfd mapeado RW y RX compartido → `aliased-write-exec` + `memfd-exec`, con la línea del lado escribible; archivo ejecutable borrado mientras está mapeado → `deleted-exec` (y antes, `exec-outside-prefixes`); la CLI contra el PID del test devuelve 1, y 2 o 0 donde corresponde.
- Los tests en vivo se serializan: cambian el mapa del propio proceso y en paralelo se corrían los números de línea entre lecturas (falló así la primera vez).
- El kernel de la VM de desarrollo no tiene `CONFIG_ANON_VMA_NAME`, así que ahí la parte de regiones nombradas se saltea con aviso; en CI se exige (`MAPS_GUARD_REQUIRE_ANON_NAME=1`).
- Mutaciones de control: clasificar mal `deleted-exec` falla un test de fixtures y uno en vivo; detectar alias sin exigir mapeo compartido da falsos positivos con cualquier `.so` y fallan 3 tests.

**Resultado real**: en la VM de desarrollo se leyeron los mapas de 101 procesos; solo aparecieron `write-exec` en procesos Node.js (páginas RWX del JIT de V8) y en un demonio de escritorio. Es el tipo de hallazgo que la lista permitida existe para documentar, no para ocultar en silencio.

**Límites**: es una foto, no un monitor: un atacante puede mapear, ejecutar y desmapear entre lecturas. No ve `mprotect` en memoria que `maps` no distingue (p. ej. permisos de `pkey`). Leer `/proc/<pid>/maps` de otro usuario requiere permisos de ptrace.

## English

**Rules**: see the table above. `[vdso]` and `[vsyscall]` are executable but not anonymous memory. `[anon:<name>]` regions (named with `prctl(PR_SET_VMA_ANON_NAME)`, as some JITs do) can be allowed by name with `--allow-anon-exec` or `--allow-write-exec`; an unnamed region is never allowed.

**Parser**: the full proc(5) format: addresses of any width, `p`/`s`, hex `major:minor` device, paths with spaces, the ` (deleted)` suffix, `[anon:…]`, `[anon_shmem:…]`, `[stack:tid]` and unknown pseudo paths. Errors carry line, column and reason.

**Tests** (`cargo test`)

- Parser (5): every backing kind; 13 malformed lines, each with its exact column; the real `/proc/self/maps` sorted and non-overlapping; proptest `Display` → `parse` round-trip with spaced paths and memfds; arbitrary text without a panic.
- Rules on fixtures (4): a normal process (x86-64, with libc, vdso and vsyscall) clean even with `--exec-prefix /usr/`; a suspicious table where every rule fires on the exact line; allowlists and prefixes; severity order.
- Live (5), real mappings created by the test itself: the test process starts clean; RWX `mmap` → `write-exec` with the right range; `mprotect` to RX → `anon-exec`; named with `PR_SET_VMA_ANON_NAME` and allowed by name; a memfd mapped shared RW and RX → `aliased-write-exec` + `memfd-exec`, pointing at the writable side's line; an executable file deleted while mapped → `deleted-exec` (and before that, `exec-outside-prefixes`); the CLI against the test's PID exits 1, and 2 or 0 where it should.
- Live tests are serialized: they change the process's own map, and in parallel the line numbers shifted between reads (that is how they failed the first time).
- The development VM's kernel lacks `CONFIG_ANON_VMA_NAME`, so the named-region part is skipped there with a notice; CI requires it (`MAPS_GUARD_REQUIRE_ANON_NAME=1`).
- Control mutations: misclassifying `deleted-exec` fails a fixture test and a live test; alias detection without requiring shared mappings flags every `.so` and 3 tests fail.

**Real-world run**: on the development VM the maps of 101 processes were readable; `write-exec` showed up only in Node.js processes (V8 JIT RWX pages) and in one desktop daemon. That is the kind of finding the allowlist exists to document, not to hide silently.

**Limits**: a snapshot, not a monitor: an attacker can map, run and unmap between reads. It cannot see protections `maps` does not show (e.g. `pkey` permissions). Reading another user's `/proc/<pid>/maps` needs ptrace permission.

## License

Apache-2.0
