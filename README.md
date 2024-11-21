![](image.png)

# bninja-ps3

Work-in-process Cell PPU (*Playstation 3*) ELF loader for Binary Ninja 4.x

Only supports decrypted PS3 executable ELFs (`EBOOT.BIN`). Not compatible with libraries (`.sprx`), system modules, or other ELF types.

Tested with Binary Ninja:
* `4.1.5902-stable`
* `4.2.6455-stable.`

# Known Issues

* syscalls are not defined
* DWARF symbols are not recognized
* bninja does not lift many PPC instructions:
```
clrldi
lfs
fcmpu
stfs
lfd
fmuls
fadds
fmadds
fdivs
mtocrf
frsp
fcfid
cmpdi
fmr
stfd
vmaddfp
psq_lx
stvx
```

## License

This plugin is released under an [MIT license](./license).

## Resources

* https://www.psdevwiki.com/ps3/SELF_-_SPRX
* http://www.openwatcom.com/ftp/devel/docs/elf-64-gen.pdf
* https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html
* https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
* https://github.com/clienthax/Ps3GhidraScripts
* https://github.com/RPCS3/rpcs3/
* https://binary.ninja/2020/01/08/guide-to-architecture-plugins-part1.html
* https://gist.github.com/xerpi/4aaf83ca59c33190c960881e3a364627#file-nidreader-py
* https://www.psdevwiki.com/ps3/PRX#PS3