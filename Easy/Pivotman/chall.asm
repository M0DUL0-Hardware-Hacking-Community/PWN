
/home/gluppler/Downloads/CTFs-Testing/Pwn/Easy/Pivotman/pwn_pivotman/challenge/chall:     file format elf64-x86-64


Disassembly of section .init:

0000000000002000 <.init>:
    2000:	48 83 ec 08          	sub    $0x8,%rsp
    2004:	48 8b 05 dd 3f 00 00 	mov    0x3fdd(%rip),%rax        # 5fe8 <__cxa_finalize@plt+0x3d68>
    200b:	48 85 c0             	test   %rax,%rax
    200e:	74 02                	je     2012 <free@plt-0x1e>
    2010:	ff d0                	call   *%rax
    2012:	48 83 c4 08          	add    $0x8,%rsp
    2016:	c3                   	ret

Disassembly of section .plt:

0000000000002020 <free@plt-0x10>:
    2020:	ff 35 7a 3e 00 00    	push   0x3e7a(%rip)        # 5ea0 <__cxa_finalize@plt+0x3c20>
    2026:	ff 25 7c 3e 00 00    	jmp    *0x3e7c(%rip)        # 5ea8 <__cxa_finalize@plt+0x3c28>
    202c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000002030 <free@plt>:
    2030:	ff 25 7a 3e 00 00    	jmp    *0x3e7a(%rip)        # 5eb0 <__cxa_finalize@plt+0x3c30>
    2036:	68 00 00 00 00       	push   $0x0
    203b:	e9 e0 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002040 <remove@plt>:
    2040:	ff 25 72 3e 00 00    	jmp    *0x3e72(%rip)        # 5eb8 <__cxa_finalize@plt+0x3c38>
    2046:	68 01 00 00 00       	push   $0x1
    204b:	e9 d0 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002050 <_exit@plt>:
    2050:	ff 25 6a 3e 00 00    	jmp    *0x3e6a(%rip)        # 5ec0 <__cxa_finalize@plt+0x3c40>
    2056:	68 02 00 00 00       	push   $0x2
    205b:	e9 c0 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002060 <strcpy@plt>:
    2060:	ff 25 62 3e 00 00    	jmp    *0x3e62(%rip)        # 5ec8 <__cxa_finalize@plt+0x3c48>
    2066:	68 03 00 00 00       	push   $0x3
    206b:	e9 b0 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002070 <mkdir@plt>:
    2070:	ff 25 5a 3e 00 00    	jmp    *0x3e5a(%rip)        # 5ed0 <__cxa_finalize@plt+0x3c50>
    2076:	68 04 00 00 00       	push   $0x4
    207b:	e9 a0 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002080 <puts@plt>:
    2080:	ff 25 52 3e 00 00    	jmp    *0x3e52(%rip)        # 5ed8 <__cxa_finalize@plt+0x3c58>
    2086:	68 05 00 00 00       	push   $0x5
    208b:	e9 90 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002090 <fread@plt>:
    2090:	ff 25 4a 3e 00 00    	jmp    *0x3e4a(%rip)        # 5ee0 <__cxa_finalize@plt+0x3c60>
    2096:	68 06 00 00 00       	push   $0x6
    209b:	e9 80 ff ff ff       	jmp    2020 <free@plt-0x10>

00000000000020a0 <vsnprintf@plt>:
    20a0:	ff 25 42 3e 00 00    	jmp    *0x3e42(%rip)        # 5ee8 <__cxa_finalize@plt+0x3c68>
    20a6:	68 07 00 00 00       	push   $0x7
    20ab:	e9 70 ff ff ff       	jmp    2020 <free@plt-0x10>

00000000000020b0 <write@plt>:
    20b0:	ff 25 3a 3e 00 00    	jmp    *0x3e3a(%rip)        # 5ef0 <__cxa_finalize@plt+0x3c70>
    20b6:	68 08 00 00 00       	push   $0x8
    20bb:	e9 60 ff ff ff       	jmp    2020 <free@plt-0x10>

00000000000020c0 <inet_ntoa@plt>:
    20c0:	ff 25 32 3e 00 00    	jmp    *0x3e32(%rip)        # 5ef8 <__cxa_finalize@plt+0x3c78>
    20c6:	68 09 00 00 00       	push   $0x9
    20cb:	e9 50 ff ff ff       	jmp    2020 <free@plt-0x10>

00000000000020d0 <fclose@plt>:
    20d0:	ff 25 2a 3e 00 00    	jmp    *0x3e2a(%rip)        # 5f00 <__cxa_finalize@plt+0x3c80>
    20d6:	68 0a 00 00 00       	push   $0xa
    20db:	e9 40 ff ff ff       	jmp    2020 <free@plt-0x10>

00000000000020e0 <rmdir@plt>:
    20e0:	ff 25 22 3e 00 00    	jmp    *0x3e22(%rip)        # 5f08 <__cxa_finalize@plt+0x3c88>
    20e6:	68 0b 00 00 00       	push   $0xb
    20eb:	e9 30 ff ff ff       	jmp    2020 <free@plt-0x10>

00000000000020f0 <strlen@plt>:
    20f0:	ff 25 1a 3e 00 00    	jmp    *0x3e1a(%rip)        # 5f10 <__cxa_finalize@plt+0x3c90>
    20f6:	68 0c 00 00 00       	push   $0xc
    20fb:	e9 20 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002100 <chdir@plt>:
    2100:	ff 25 12 3e 00 00    	jmp    *0x3e12(%rip)        # 5f18 <__cxa_finalize@plt+0x3c98>
    2106:	68 0d 00 00 00       	push   $0xd
    210b:	e9 10 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002110 <pclose@plt>:
    2110:	ff 25 0a 3e 00 00    	jmp    *0x3e0a(%rip)        # 5f20 <__cxa_finalize@plt+0x3ca0>
    2116:	68 0e 00 00 00       	push   $0xe
    211b:	e9 00 ff ff ff       	jmp    2020 <free@plt-0x10>

0000000000002120 <gmtime_r@plt>:
    2120:	ff 25 02 3e 00 00    	jmp    *0x3e02(%rip)        # 5f28 <__cxa_finalize@plt+0x3ca8>
    2126:	68 0f 00 00 00       	push   $0xf
    212b:	e9 f0 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002130 <htonl@plt>:
    2130:	ff 25 fa 3d 00 00    	jmp    *0x3dfa(%rip)        # 5f30 <__cxa_finalize@plt+0x3cb0>
    2136:	68 10 00 00 00       	push   $0x10
    213b:	e9 e0 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002140 <memset@plt>:
    2140:	ff 25 f2 3d 00 00    	jmp    *0x3df2(%rip)        # 5f38 <__cxa_finalize@plt+0x3cb8>
    2146:	68 11 00 00 00       	push   $0x11
    214b:	e9 d0 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002150 <getcwd@plt>:
    2150:	ff 25 ea 3d 00 00    	jmp    *0x3dea(%rip)        # 5f40 <__cxa_finalize@plt+0x3cc0>
    2156:	68 12 00 00 00       	push   $0x12
    215b:	e9 c0 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002160 <read@plt>:
    2160:	ff 25 e2 3d 00 00    	jmp    *0x3de2(%rip)        # 5f48 <__cxa_finalize@plt+0x3cc8>
    2166:	68 13 00 00 00       	push   $0x13
    216b:	e9 b0 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002170 <srand@plt>:
    2170:	ff 25 da 3d 00 00    	jmp    *0x3dda(%rip)        # 5f50 <__cxa_finalize@plt+0x3cd0>
    2176:	68 14 00 00 00       	push   $0x14
    217b:	e9 a0 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002180 <strcmp@plt>:
    2180:	ff 25 d2 3d 00 00    	jmp    *0x3dd2(%rip)        # 5f58 <__cxa_finalize@plt+0x3cd8>
    2186:	68 15 00 00 00       	push   $0x15
    218b:	e9 90 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002190 <stat@plt>:
    2190:	ff 25 ca 3d 00 00    	jmp    *0x3dca(%rip)        # 5f60 <__cxa_finalize@plt+0x3ce0>
    2196:	68 16 00 00 00       	push   $0x16
    219b:	e9 80 fe ff ff       	jmp    2020 <free@plt-0x10>

00000000000021a0 <memcpy@plt>:
    21a0:	ff 25 c2 3d 00 00    	jmp    *0x3dc2(%rip)        # 5f68 <__cxa_finalize@plt+0x3ce8>
    21a6:	68 17 00 00 00       	push   $0x17
    21ab:	e9 70 fe ff ff       	jmp    2020 <free@plt-0x10>

00000000000021b0 <time@plt>:
    21b0:	ff 25 ba 3d 00 00    	jmp    *0x3dba(%rip)        # 5f70 <__cxa_finalize@plt+0x3cf0>
    21b6:	68 18 00 00 00       	push   $0x18
    21bb:	e9 60 fe ff ff       	jmp    2020 <free@plt-0x10>

00000000000021c0 <malloc@plt>:
    21c0:	ff 25 b2 3d 00 00    	jmp    *0x3db2(%rip)        # 5f78 <__cxa_finalize@plt+0x3cf8>
    21c6:	68 19 00 00 00       	push   $0x19
    21cb:	e9 50 fe ff ff       	jmp    2020 <free@plt-0x10>

00000000000021d0 <fseek@plt>:
    21d0:	ff 25 aa 3d 00 00    	jmp    *0x3daa(%rip)        # 5f80 <__cxa_finalize@plt+0x3d00>
    21d6:	68 1a 00 00 00       	push   $0x1a
    21db:	e9 40 fe ff ff       	jmp    2020 <free@plt-0x10>

00000000000021e0 <strftime@plt>:
    21e0:	ff 25 a2 3d 00 00    	jmp    *0x3da2(%rip)        # 5f88 <__cxa_finalize@plt+0x3d08>
    21e6:	68 1b 00 00 00       	push   $0x1b
    21eb:	e9 30 fe ff ff       	jmp    2020 <free@plt-0x10>

00000000000021f0 <getspnam@plt>:
    21f0:	ff 25 9a 3d 00 00    	jmp    *0x3d9a(%rip)        # 5f90 <__cxa_finalize@plt+0x3d10>
    21f6:	68 1c 00 00 00       	push   $0x1c
    21fb:	e9 20 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002200 <access@plt>:
    2200:	ff 25 92 3d 00 00    	jmp    *0x3d92(%rip)        # 5f98 <__cxa_finalize@plt+0x3d18>
    2206:	68 1d 00 00 00       	push   $0x1d
    220b:	e9 10 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002210 <popen@plt>:
    2210:	ff 25 8a 3d 00 00    	jmp    *0x3d8a(%rip)        # 5fa0 <__cxa_finalize@plt+0x3d20>
    2216:	68 1e 00 00 00       	push   $0x1e
    221b:	e9 00 fe ff ff       	jmp    2020 <free@plt-0x10>

0000000000002220 <fopen@plt>:
    2220:	ff 25 82 3d 00 00    	jmp    *0x3d82(%rip)        # 5fa8 <__cxa_finalize@plt+0x3d28>
    2226:	68 1f 00 00 00       	push   $0x1f
    222b:	e9 f0 fd ff ff       	jmp    2020 <free@plt-0x10>

0000000000002230 <rename@plt>:
    2230:	ff 25 7a 3d 00 00    	jmp    *0x3d7a(%rip)        # 5fb0 <__cxa_finalize@plt+0x3d30>
    2236:	68 20 00 00 00       	push   $0x20
    223b:	e9 e0 fd ff ff       	jmp    2020 <free@plt-0x10>

0000000000002240 <atoi@plt>:
    2240:	ff 25 72 3d 00 00    	jmp    *0x3d72(%rip)        # 5fb8 <__cxa_finalize@plt+0x3d38>
    2246:	68 21 00 00 00       	push   $0x21
    224b:	e9 d0 fd ff ff       	jmp    2020 <free@plt-0x10>

0000000000002250 <sprintf@plt>:
    2250:	ff 25 6a 3d 00 00    	jmp    *0x3d6a(%rip)        # 5fc0 <__cxa_finalize@plt+0x3d40>
    2256:	68 22 00 00 00       	push   $0x22
    225b:	e9 c0 fd ff ff       	jmp    2020 <free@plt-0x10>

0000000000002260 <fwrite@plt>:
    2260:	ff 25 62 3d 00 00    	jmp    *0x3d62(%rip)        # 5fc8 <__cxa_finalize@plt+0x3d48>
    2266:	68 23 00 00 00       	push   $0x23
    226b:	e9 b0 fd ff ff       	jmp    2020 <free@plt-0x10>

0000000000002270 <__ctype_b_loc@plt>:
    2270:	ff 25 5a 3d 00 00    	jmp    *0x3d5a(%rip)        # 5fd0 <__cxa_finalize@plt+0x3d50>
    2276:	68 24 00 00 00       	push   $0x24
    227b:	e9 a0 fd ff ff       	jmp    2020 <free@plt-0x10>

Disassembly of section .plt.got:

0000000000002280 <__cxa_finalize@plt>:
    2280:	ff 25 72 3d 00 00    	jmp    *0x3d72(%rip)        # 5ff8 <__cxa_finalize@plt+0x3d78>
    2286:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000002290 <.text>:
    2290:	31 ed                	xor    %ebp,%ebp
    2292:	49 89 d1             	mov    %rdx,%r9
    2295:	5e                   	pop    %rsi
    2296:	48 89 e2             	mov    %rsp,%rdx
    2299:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    229d:	50                   	push   %rax
    229e:	54                   	push   %rsp
    229f:	4c 8d 05 ea 17 00 00 	lea    0x17ea(%rip),%r8        # 3a90 <__cxa_finalize@plt+0x1810>
    22a6:	48 8d 0d 83 17 00 00 	lea    0x1783(%rip),%rcx        # 3a30 <__cxa_finalize@plt+0x17b0>
    22ad:	48 8d 3d 4e 17 00 00 	lea    0x174e(%rip),%rdi        # 3a02 <__cxa_finalize@plt+0x1782>
    22b4:	ff 15 26 3d 00 00    	call   *0x3d26(%rip)        # 5fe0 <__cxa_finalize@plt+0x3d60>
    22ba:	f4                   	hlt
    22bb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
    22c0:	48 8d 3d 39 3f 00 00 	lea    0x3f39(%rip),%rdi        # 6200 <__cxa_finalize@plt+0x3f80>
    22c7:	48 8d 05 32 3f 00 00 	lea    0x3f32(%rip),%rax        # 6200 <__cxa_finalize@plt+0x3f80>
    22ce:	48 39 f8             	cmp    %rdi,%rax
    22d1:	74 15                	je     22e8 <__cxa_finalize@plt+0x68>
    22d3:	48 8b 05 fe 3c 00 00 	mov    0x3cfe(%rip),%rax        # 5fd8 <__cxa_finalize@plt+0x3d58>
    22da:	48 85 c0             	test   %rax,%rax
    22dd:	74 09                	je     22e8 <__cxa_finalize@plt+0x68>
    22df:	ff e0                	jmp    *%rax
    22e1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    22e8:	c3                   	ret
    22e9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    22f0:	48 8d 3d 09 3f 00 00 	lea    0x3f09(%rip),%rdi        # 6200 <__cxa_finalize@plt+0x3f80>
    22f7:	48 8d 35 02 3f 00 00 	lea    0x3f02(%rip),%rsi        # 6200 <__cxa_finalize@plt+0x3f80>
    22fe:	48 29 fe             	sub    %rdi,%rsi
    2301:	48 89 f0             	mov    %rsi,%rax
    2304:	48 c1 ee 3f          	shr    $0x3f,%rsi
    2308:	48 c1 f8 03          	sar    $0x3,%rax
    230c:	48 01 c6             	add    %rax,%rsi
    230f:	48 d1 fe             	sar    $1,%rsi
    2312:	74 14                	je     2328 <__cxa_finalize@plt+0xa8>
    2314:	48 8b 05 d5 3c 00 00 	mov    0x3cd5(%rip),%rax        # 5ff0 <__cxa_finalize@plt+0x3d70>
    231b:	48 85 c0             	test   %rax,%rax
    231e:	74 08                	je     2328 <__cxa_finalize@plt+0xa8>
    2320:	ff e0                	jmp    *%rax
    2322:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    2328:	c3                   	ret
    2329:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    2330:	f3 0f 1e fa          	endbr64
    2334:	80 3d c5 3e 00 00 00 	cmpb   $0x0,0x3ec5(%rip)        # 6200 <__cxa_finalize@plt+0x3f80>
    233b:	75 2b                	jne    2368 <__cxa_finalize@plt+0xe8>
    233d:	55                   	push   %rbp
    233e:	48 83 3d b2 3c 00 00 	cmpq   $0x0,0x3cb2(%rip)        # 5ff8 <__cxa_finalize@plt+0x3d78>
    2345:	00 
    2346:	48 89 e5             	mov    %rsp,%rbp
    2349:	74 0c                	je     2357 <__cxa_finalize@plt+0xd7>
    234b:	48 8b 3d b6 3c 00 00 	mov    0x3cb6(%rip),%rdi        # 6008 <__cxa_finalize@plt+0x3d88>
    2352:	e8 29 ff ff ff       	call   2280 <__cxa_finalize@plt>
    2357:	e8 64 ff ff ff       	call   22c0 <__cxa_finalize@plt+0x40>
    235c:	c6 05 9d 3e 00 00 01 	movb   $0x1,0x3e9d(%rip)        # 6200 <__cxa_finalize@plt+0x3f80>
    2363:	5d                   	pop    %rbp
    2364:	c3                   	ret
    2365:	0f 1f 00             	nopl   (%rax)
    2368:	c3                   	ret
    2369:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    2370:	f3 0f 1e fa          	endbr64
    2374:	e9 77 ff ff ff       	jmp    22f0 <__cxa_finalize@plt+0x70>
    2379:	55                   	push   %rbp
    237a:	48 89 e5             	mov    %rsp,%rbp
    237d:	48 81 ec e0 10 00 00 	sub    $0x10e0,%rsp
    2384:	48 89 bd 28 ef ff ff 	mov    %rdi,-0x10d8(%rbp)
    238b:	48 89 b5 58 ff ff ff 	mov    %rsi,-0xa8(%rbp)
    2392:	48 89 95 60 ff ff ff 	mov    %rdx,-0xa0(%rbp)
    2399:	48 89 8d 68 ff ff ff 	mov    %rcx,-0x98(%rbp)
    23a0:	4c 89 85 70 ff ff ff 	mov    %r8,-0x90(%rbp)
    23a7:	4c 89 8d 78 ff ff ff 	mov    %r9,-0x88(%rbp)
    23ae:	84 c0                	test   %al,%al
    23b0:	74 20                	je     23d2 <__cxa_finalize@plt+0x152>
    23b2:	0f 29 45 80          	movaps %xmm0,-0x80(%rbp)
    23b6:	0f 29 4d 90          	movaps %xmm1,-0x70(%rbp)
    23ba:	0f 29 55 a0          	movaps %xmm2,-0x60(%rbp)
    23be:	0f 29 5d b0          	movaps %xmm3,-0x50(%rbp)
    23c2:	0f 29 65 c0          	movaps %xmm4,-0x40(%rbp)
    23c6:	0f 29 6d d0          	movaps %xmm5,-0x30(%rbp)
    23ca:	0f 29 75 e0          	movaps %xmm6,-0x20(%rbp)
    23ce:	0f 29 7d f0          	movaps %xmm7,-0x10(%rbp)
    23d2:	c7 85 38 ff ff ff 08 	movl   $0x8,-0xc8(%rbp)
    23d9:	00 00 00 
    23dc:	c7 85 3c ff ff ff 30 	movl   $0x30,-0xc4(%rbp)
    23e3:	00 00 00 
    23e6:	48 8d 45 10          	lea    0x10(%rbp),%rax
    23ea:	48 89 85 40 ff ff ff 	mov    %rax,-0xc0(%rbp)
    23f1:	48 8d 85 50 ff ff ff 	lea    -0xb0(%rbp),%rax
    23f8:	48 89 85 48 ff ff ff 	mov    %rax,-0xb8(%rbp)
    23ff:	48 8d 8d 38 ff ff ff 	lea    -0xc8(%rbp),%rcx
    2406:	48 8b 95 28 ef ff ff 	mov    -0x10d8(%rbp),%rdx
    240d:	48 8d 85 30 ef ff ff 	lea    -0x10d0(%rbp),%rax
    2414:	be 00 10 00 00       	mov    $0x1000,%esi
    2419:	48 89 c7             	mov    %rax,%rdi
    241c:	e8 7f fc ff ff       	call   20a0 <vsnprintf@plt>
    2421:	48 8d 85 30 ef ff ff 	lea    -0x10d0(%rbp),%rax
    2428:	48 89 c7             	mov    %rax,%rdi
    242b:	e8 c0 fc ff ff       	call   20f0 <strlen@plt>
    2430:	48 89 c2             	mov    %rax,%rdx
    2433:	48 8d 85 30 ef ff ff 	lea    -0x10d0(%rbp),%rax
    243a:	48 89 c6             	mov    %rax,%rsi
    243d:	bf 01 00 00 00       	mov    $0x1,%edi
    2442:	e8 69 fc ff ff       	call   20b0 <write@plt>
    2447:	c9                   	leave
    2448:	c3                   	ret
    2449:	55                   	push   %rbp
    244a:	48 89 e5             	mov    %rsp,%rbp
    244d:	48 81 ec 20 10 00 00 	sub    $0x1020,%rsp
    2454:	48 89 bd e8 ef ff ff 	mov    %rdi,-0x1018(%rbp)
    245b:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    2462:	eb 39                	jmp    249d <__cxa_finalize@plt+0x21d>
    2464:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2467:	48 63 d0             	movslq %eax,%rdx
    246a:	48 8d 85 f0 ef ff ff 	lea    -0x1010(%rbp),%rax
    2471:	48 89 c6             	mov    %rax,%rsi
    2474:	bf 01 00 00 00       	mov    $0x1,%edi
    2479:	e8 32 fc ff ff       	call   20b0 <write@plt>
    247e:	89 45 f4             	mov    %eax,-0xc(%rbp)
    2481:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    2485:	79 09                	jns    2490 <__cxa_finalize@plt+0x210>
    2487:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)
    248e:	eb 39                	jmp    24c9 <__cxa_finalize@plt+0x249>
    2490:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2493:	48 98                	cltq
    2495:	c6 84 05 f0 ef ff ff 	movb   $0x0,-0x1010(%rbp,%rax,1)
    249c:	00 
    249d:	48 8b 95 e8 ef ff ff 	mov    -0x1018(%rbp),%rdx
    24a4:	48 8d 85 f0 ef ff ff 	lea    -0x1010(%rbp),%rax
    24ab:	48 89 d1             	mov    %rdx,%rcx
    24ae:	ba 00 10 00 00       	mov    $0x1000,%edx
    24b3:	be 01 00 00 00       	mov    $0x1,%esi
    24b8:	48 89 c7             	mov    %rax,%rdi
    24bb:	e8 d0 fb ff ff       	call   2090 <fread@plt>
    24c0:	89 45 f8             	mov    %eax,-0x8(%rbp)
    24c3:	83 7d f8 00          	cmpl   $0x0,-0x8(%rbp)
    24c7:	7f 9b                	jg     2464 <__cxa_finalize@plt+0x1e4>
    24c9:	8b 45 fc             	mov    -0x4(%rbp),%eax
    24cc:	c9                   	leave
    24cd:	c3                   	ret
    24ce:	55                   	push   %rbp
    24cf:	48 89 e5             	mov    %rsp,%rbp
    24d2:	48 83 ec 20          	sub    $0x20,%rsp
    24d6:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    24da:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    24dd:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    24e1:	48 8d 15 b2 1b 00 00 	lea    0x1bb2(%rip),%rdx        # 409a <__cxa_finalize@plt+0x1e1a>
    24e8:	48 89 d6             	mov    %rdx,%rsi
    24eb:	48 89 c7             	mov    %rax,%rdi
    24ee:	e8 2d fd ff ff       	call   2220 <fopen@plt>
    24f3:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    24f7:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    24fc:	74 33                	je     2531 <__cxa_finalize@plt+0x2b1>
    24fe:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    2501:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2505:	ba 00 00 00 00       	mov    $0x0,%edx
    250a:	48 89 ce             	mov    %rcx,%rsi
    250d:	48 89 c7             	mov    %rax,%rdi
    2510:	e8 bb fc ff ff       	call   21d0 <fseek@plt>
    2515:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2519:	48 89 c7             	mov    %rax,%rdi
    251c:	e8 28 ff ff ff       	call   2449 <__cxa_finalize@plt+0x1c9>
    2521:	89 45 f4             	mov    %eax,-0xc(%rbp)
    2524:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    2528:	79 0e                	jns    2538 <__cxa_finalize@plt+0x2b8>
    252a:	b8 fe ff ff ff       	mov    $0xfffffffe,%eax
    252f:	eb 28                	jmp    2559 <__cxa_finalize@plt+0x2d9>
    2531:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2536:	eb 21                	jmp    2559 <__cxa_finalize@plt+0x2d9>
    2538:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    253c:	48 89 c7             	mov    %rax,%rdi
    253f:	e8 8c fb ff ff       	call   20d0 <fclose@plt>
    2544:	89 45 f0             	mov    %eax,-0x10(%rbp)
    2547:	83 7d f0 00          	cmpl   $0x0,-0x10(%rbp)
    254b:	75 07                	jne    2554 <__cxa_finalize@plt+0x2d4>
    254d:	b8 00 00 00 00       	mov    $0x0,%eax
    2552:	eb 05                	jmp    2559 <__cxa_finalize@plt+0x2d9>
    2554:	b8 fd ff ff ff       	mov    $0xfffffffd,%eax
    2559:	c9                   	leave
    255a:	c3                   	ret
    255b:	55                   	push   %rbp
    255c:	48 89 e5             	mov    %rsp,%rbp
    255f:	48 81 ec 20 10 00 00 	sub    $0x1020,%rsp
    2566:	48 89 bd e8 ef ff ff 	mov    %rdi,-0x1018(%rbp)
    256d:	eb 21                	jmp    2590 <__cxa_finalize@plt+0x310>
    256f:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2572:	48 63 d0             	movslq %eax,%rdx
    2575:	48 8b 8d e8 ef ff ff 	mov    -0x1018(%rbp),%rcx
    257c:	48 8d 85 f0 ef ff ff 	lea    -0x1010(%rbp),%rax
    2583:	be 01 00 00 00       	mov    $0x1,%esi
    2588:	48 89 c7             	mov    %rax,%rdi
    258b:	e8 d0 fc ff ff       	call   2260 <fwrite@plt>
    2590:	48 8d 85 f0 ef ff ff 	lea    -0x1010(%rbp),%rax
    2597:	ba 00 10 00 00       	mov    $0x1000,%edx
    259c:	48 89 c6             	mov    %rax,%rsi
    259f:	bf 00 00 00 00       	mov    $0x0,%edi
    25a4:	e8 b7 fb ff ff       	call   2160 <read@plt>
    25a9:	89 45 fc             	mov    %eax,-0x4(%rbp)
    25ac:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    25b0:	7f bd                	jg     256f <__cxa_finalize@plt+0x2ef>
    25b2:	8b 45 fc             	mov    -0x4(%rbp),%eax
    25b5:	c9                   	leave
    25b6:	c3                   	ret
    25b7:	55                   	push   %rbp
    25b8:	48 89 e5             	mov    %rsp,%rbp
    25bb:	48 83 ec 20          	sub    $0x20,%rsp
    25bf:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    25c3:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    25c6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    25ca:	48 8d 15 cc 1a 00 00 	lea    0x1acc(%rip),%rdx        # 409d <__cxa_finalize@plt+0x1e1d>
    25d1:	48 89 d6             	mov    %rdx,%rsi
    25d4:	48 89 c7             	mov    %rax,%rdi
    25d7:	e8 44 fc ff ff       	call   2220 <fopen@plt>
    25dc:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    25e0:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
    25e5:	75 07                	jne    25ee <__cxa_finalize@plt+0x36e>
    25e7:	b8 fe ff ff ff       	mov    $0xfffffffe,%eax
    25ec:	eb 43                	jmp    2631 <__cxa_finalize@plt+0x3b1>
    25ee:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
    25f1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    25f5:	ba 00 00 00 00       	mov    $0x0,%edx
    25fa:	48 89 ce             	mov    %rcx,%rsi
    25fd:	48 89 c7             	mov    %rax,%rdi
    2600:	e8 cb fb ff ff       	call   21d0 <fseek@plt>
    2605:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2609:	48 89 c7             	mov    %rax,%rdi
    260c:	e8 4a ff ff ff       	call   255b <__cxa_finalize@plt+0x2db>
    2611:	89 45 f4             	mov    %eax,-0xc(%rbp)
    2614:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2618:	48 89 c7             	mov    %rax,%rdi
    261b:	e8 b0 fa ff ff       	call   20d0 <fclose@plt>
    2620:	89 45 f0             	mov    %eax,-0x10(%rbp)
    2623:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    2627:	79 05                	jns    262e <__cxa_finalize@plt+0x3ae>
    2629:	8b 45 f4             	mov    -0xc(%rbp),%eax
    262c:	eb 03                	jmp    2631 <__cxa_finalize@plt+0x3b1>
    262e:	8b 45 f0             	mov    -0x10(%rbp),%eax
    2631:	c9                   	leave
    2632:	c3                   	ret
    2633:	55                   	push   %rbp
    2634:	48 89 e5             	mov    %rsp,%rbp
    2637:	48 81 ec 20 10 00 00 	sub    $0x1020,%rsp
    263e:	48 89 bd e8 ef ff ff 	mov    %rdi,-0x1018(%rbp)
    2645:	48 89 b5 e0 ef ff ff 	mov    %rsi,-0x1020(%rbp)
    264c:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)
    2653:	48 c7 85 f0 ef ff ff 	movq   $0x0,-0x1010(%rbp)
    265a:	00 00 00 00 
    265e:	48 c7 85 f8 ef ff ff 	movq   $0x0,-0x1008(%rbp)
    2665:	00 00 00 00 
    2669:	48 8d 95 00 f0 ff ff 	lea    -0x1000(%rbp),%rdx
    2670:	b8 00 00 00 00       	mov    $0x0,%eax
    2675:	b9 fe 01 00 00       	mov    $0x1fe,%ecx
    267a:	48 89 d7             	mov    %rdx,%rdi
    267d:	f3 48 ab             	rep stos %rax,(%rdi)
    2680:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%rbp)
    2687:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    268e:	e9 af 00 00 00       	jmp    2742 <__cxa_finalize@plt+0x4c2>
    2693:	e8 d8 fb ff ff       	call   2270 <__ctype_b_loc@plt>
    2698:	48 8b 10             	mov    (%rax),%rdx
    269b:	8b 45 f8             	mov    -0x8(%rbp),%eax
    269e:	48 63 c8             	movslq %eax,%rcx
    26a1:	48 8b 85 e8 ef ff ff 	mov    -0x1018(%rbp),%rax
    26a8:	48 01 c8             	add    %rcx,%rax
    26ab:	0f b6 00             	movzbl (%rax),%eax
    26ae:	48 0f be c0          	movsbq %al,%rax
    26b2:	48 01 c0             	add    %rax,%rax
    26b5:	48 01 d0             	add    %rdx,%rax
    26b8:	0f b7 00             	movzwl (%rax),%eax
    26bb:	0f b7 c0             	movzwl %ax,%eax
    26be:	25 00 08 00 00       	and    $0x800,%eax
    26c3:	85 c0                	test   %eax,%eax
    26c5:	75 6b                	jne    2732 <__cxa_finalize@plt+0x4b2>
    26c7:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    26cb:	78 71                	js     273e <__cxa_finalize@plt+0x4be>
    26cd:	8b 45 f8             	mov    -0x8(%rbp),%eax
    26d0:	2b 45 fc             	sub    -0x4(%rbp),%eax
    26d3:	48 63 d0             	movslq %eax,%rdx
    26d6:	8b 45 fc             	mov    -0x4(%rbp),%eax
    26d9:	48 63 c8             	movslq %eax,%rcx
    26dc:	48 8b 85 e8 ef ff ff 	mov    -0x1018(%rbp),%rax
    26e3:	48 01 c1             	add    %rax,%rcx
    26e6:	48 8d 85 f0 ef ff ff 	lea    -0x1010(%rbp),%rax
    26ed:	48 89 ce             	mov    %rcx,%rsi
    26f0:	48 89 c7             	mov    %rax,%rdi
    26f3:	e8 a8 fa ff ff       	call   21a0 <memcpy@plt>
    26f8:	8b 45 f8             	mov    -0x8(%rbp),%eax
    26fb:	2b 45 fc             	sub    -0x4(%rbp),%eax
    26fe:	48 98                	cltq
    2700:	c6 84 05 f0 ef ff ff 	movb   $0x0,-0x1010(%rbp,%rax,1)
    2707:	00 
    2708:	48 8d 85 f0 ef ff ff 	lea    -0x1010(%rbp),%rax
    270f:	48 89 c7             	mov    %rax,%rdi
    2712:	e8 29 fb ff ff       	call   2240 <atoi@plt>
    2717:	89 c2                	mov    %eax,%edx
    2719:	48 8b 85 e0 ef ff ff 	mov    -0x1020(%rbp),%rax
    2720:	89 10                	mov    %edx,(%rax)
    2722:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
    2729:	c7 45 fc ff ff ff ff 	movl   $0xffffffff,-0x4(%rbp)
    2730:	eb 34                	jmp    2766 <__cxa_finalize@plt+0x4e6>
    2732:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
    2736:	79 06                	jns    273e <__cxa_finalize@plt+0x4be>
    2738:	8b 45 f8             	mov    -0x8(%rbp),%eax
    273b:	89 45 fc             	mov    %eax,-0x4(%rbp)
    273e:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    2742:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2745:	48 63 d0             	movslq %eax,%rdx
    2748:	48 8b 85 e8 ef ff ff 	mov    -0x1018(%rbp),%rax
    274f:	48 01 d0             	add    %rdx,%rax
    2752:	0f b6 00             	movzbl (%rax),%eax
    2755:	84 c0                	test   %al,%al
    2757:	74 0d                	je     2766 <__cxa_finalize@plt+0x4e6>
    2759:	81 7d f8 ff 0f 00 00 	cmpl   $0xfff,-0x8(%rbp)
    2760:	0f 8e 2d ff ff ff    	jle    2693 <__cxa_finalize@plt+0x413>
    2766:	8b 45 f4             	mov    -0xc(%rbp),%eax
    2769:	c9                   	leave
    276a:	c3                   	ret
    276b:	55                   	push   %rbp
    276c:	48 89 e5             	mov    %rsp,%rbp
    276f:	53                   	push   %rbx
    2770:	48 81 ec 38 10 00 00 	sub    $0x1038,%rsp
    2777:	48 89 bd d8 ef ff ff 	mov    %rdi,-0x1028(%rbp)
    277e:	48 89 b5 d0 ef ff ff 	mov    %rsi,-0x1030(%rbp)
    2785:	48 89 95 c8 ef ff ff 	mov    %rdx,-0x1038(%rbp)
    278c:	48 8b 85 c8 ef ff ff 	mov    -0x1038(%rbp),%rax
    2793:	66 c7 00 00 00       	movw   $0x0,(%rax)
    2798:	48 8b 85 d0 ef ff ff 	mov    -0x1030(%rbp),%rax
    279f:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
    27a5:	c7 45 e8 ff ff ff ff 	movl   $0xffffffff,-0x18(%rbp)
    27ac:	48 c7 85 e0 ef ff ff 	movq   $0x0,-0x1020(%rbp)
    27b3:	00 00 00 00 
    27b7:	48 c7 85 e8 ef ff ff 	movq   $0x0,-0x1018(%rbp)
    27be:	00 00 00 00 
    27c2:	48 8d 95 f0 ef ff ff 	lea    -0x1010(%rbp),%rdx
    27c9:	b8 00 00 00 00       	mov    $0x0,%eax
    27ce:	b9 fe 01 00 00       	mov    $0x1fe,%ecx
    27d3:	48 89 d7             	mov    %rdx,%rdi
    27d6:	f3 48 ab             	rep stos %rax,(%rdi)
    27d9:	c7 45 e4 00 00 00 00 	movl   $0x0,-0x1c(%rbp)
    27e0:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
    27e7:	c7 45 ec 00 00 00 00 	movl   $0x0,-0x14(%rbp)
    27ee:	e9 06 01 00 00       	jmp    28f9 <__cxa_finalize@plt+0x679>
    27f3:	e8 78 fa ff ff       	call   2270 <__ctype_b_loc@plt>
    27f8:	48 8b 10             	mov    (%rax),%rdx
    27fb:	8b 45 ec             	mov    -0x14(%rbp),%eax
    27fe:	48 63 c8             	movslq %eax,%rcx
    2801:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
    2808:	48 01 c8             	add    %rcx,%rax
    280b:	0f b6 00             	movzbl (%rax),%eax
    280e:	48 0f be c0          	movsbq %al,%rax
    2812:	48 01 c0             	add    %rax,%rax
    2815:	48 01 d0             	add    %rdx,%rax
    2818:	0f b7 00             	movzwl (%rax),%eax
    281b:	0f b7 c0             	movzwl %ax,%eax
    281e:	25 00 08 00 00       	and    $0x800,%eax
    2823:	85 c0                	test   %eax,%eax
    2825:	0f 85 be 00 00 00    	jne    28e9 <__cxa_finalize@plt+0x669>
    282b:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
    282f:	0f 88 c0 00 00 00    	js     28f5 <__cxa_finalize@plt+0x675>
    2835:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2838:	2b 45 e8             	sub    -0x18(%rbp),%eax
    283b:	48 63 d0             	movslq %eax,%rdx
    283e:	8b 45 e8             	mov    -0x18(%rbp),%eax
    2841:	48 63 c8             	movslq %eax,%rcx
    2844:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
    284b:	48 01 c1             	add    %rax,%rcx
    284e:	48 8d 85 e0 ef ff ff 	lea    -0x1020(%rbp),%rax
    2855:	48 89 ce             	mov    %rcx,%rsi
    2858:	48 89 c7             	mov    %rax,%rdi
    285b:	e8 40 f9 ff ff       	call   21a0 <memcpy@plt>
    2860:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2863:	2b 45 e8             	sub    -0x18(%rbp),%eax
    2866:	48 98                	cltq
    2868:	c6 84 05 e0 ef ff ff 	movb   $0x0,-0x1020(%rbp,%rax,1)
    286f:	00 
    2870:	83 7d e4 03          	cmpl   $0x3,-0x1c(%rbp)
    2874:	7f 32                	jg     28a8 <__cxa_finalize@plt+0x628>
    2876:	48 8b 85 d0 ef ff ff 	mov    -0x1030(%rbp),%rax
    287d:	8b 00                	mov    (%rax),%eax
    287f:	c1 e0 08             	shl    $0x8,%eax
    2882:	89 c3                	mov    %eax,%ebx
    2884:	48 8d 85 e0 ef ff ff 	lea    -0x1020(%rbp),%rax
    288b:	48 89 c7             	mov    %rax,%rdi
    288e:	e8 ad f9 ff ff       	call   2240 <atoi@plt>
    2893:	0f b6 c0             	movzbl %al,%eax
    2896:	8d 14 03             	lea    (%rbx,%rax,1),%edx
    2899:	48 8b 85 d0 ef ff ff 	mov    -0x1030(%rbp),%rax
    28a0:	89 10                	mov    %edx,(%rax)
    28a2:	83 45 e4 01          	addl   $0x1,-0x1c(%rbp)
    28a6:	eb 38                	jmp    28e0 <__cxa_finalize@plt+0x660>
    28a8:	83 7d e0 01          	cmpl   $0x1,-0x20(%rbp)
    28ac:	7f 71                	jg     291f <__cxa_finalize@plt+0x69f>
    28ae:	48 8b 85 c8 ef ff ff 	mov    -0x1038(%rbp),%rax
    28b5:	0f b7 00             	movzwl (%rax),%eax
    28b8:	c1 e0 08             	shl    $0x8,%eax
    28bb:	89 c3                	mov    %eax,%ebx
    28bd:	48 8d 85 e0 ef ff ff 	lea    -0x1020(%rbp),%rax
    28c4:	48 89 c7             	mov    %rax,%rdi
    28c7:	e8 74 f9 ff ff       	call   2240 <atoi@plt>
    28cc:	0f b6 c0             	movzbl %al,%eax
    28cf:	8d 14 03             	lea    (%rbx,%rax,1),%edx
    28d2:	48 8b 85 c8 ef ff ff 	mov    -0x1038(%rbp),%rax
    28d9:	66 89 10             	mov    %dx,(%rax)
    28dc:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
    28e0:	c7 45 e8 ff ff ff ff 	movl   $0xffffffff,-0x18(%rbp)
    28e7:	eb 0c                	jmp    28f5 <__cxa_finalize@plt+0x675>
    28e9:	83 7d e8 00          	cmpl   $0x0,-0x18(%rbp)
    28ed:	79 06                	jns    28f5 <__cxa_finalize@plt+0x675>
    28ef:	8b 45 ec             	mov    -0x14(%rbp),%eax
    28f2:	89 45 e8             	mov    %eax,-0x18(%rbp)
    28f5:	83 45 ec 01          	addl   $0x1,-0x14(%rbp)
    28f9:	8b 45 ec             	mov    -0x14(%rbp),%eax
    28fc:	48 63 d0             	movslq %eax,%rdx
    28ff:	48 8b 85 d8 ef ff ff 	mov    -0x1028(%rbp),%rax
    2906:	48 01 d0             	add    %rdx,%rax
    2909:	0f b6 00             	movzbl (%rax),%eax
    290c:	84 c0                	test   %al,%al
    290e:	74 10                	je     2920 <__cxa_finalize@plt+0x6a0>
    2910:	81 7d ec ff 0f 00 00 	cmpl   $0xfff,-0x14(%rbp)
    2917:	0f 8e d6 fe ff ff    	jle    27f3 <__cxa_finalize@plt+0x573>
    291d:	eb 01                	jmp    2920 <__cxa_finalize@plt+0x6a0>
    291f:	90                   	nop
    2920:	83 7d e4 04          	cmpl   $0x4,-0x1c(%rbp)
    2924:	75 0d                	jne    2933 <__cxa_finalize@plt+0x6b3>
    2926:	83 7d e0 02          	cmpl   $0x2,-0x20(%rbp)
    292a:	75 07                	jne    2933 <__cxa_finalize@plt+0x6b3>
    292c:	b8 01 00 00 00       	mov    $0x1,%eax
    2931:	eb 05                	jmp    2938 <__cxa_finalize@plt+0x6b8>
    2933:	b8 00 00 00 00       	mov    $0x0,%eax
    2938:	48 8b 5d f8          	mov    -0x8(%rbp),%rbx
    293c:	c9                   	leave
    293d:	c3                   	ret
    293e:	55                   	push   %rbp
    293f:	48 89 e5             	mov    %rsp,%rbp
    2942:	48 83 ec 20          	sub    $0x20,%rsp
    2946:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    294a:	bf 00 10 00 00       	mov    $0x1000,%edi
    294f:	e8 6c f8 ff ff       	call   21c0 <malloc@plt>
    2954:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    2958:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    295f:	eb 04                	jmp    2965 <__cxa_finalize@plt+0x6e5>
    2961:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2965:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2968:	48 63 d0             	movslq %eax,%rdx
    296b:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    296f:	48 01 d0             	add    %rdx,%rax
    2972:	0f b6 00             	movzbl (%rax),%eax
    2975:	3c 20                	cmp    $0x20,%al
    2977:	74 09                	je     2982 <__cxa_finalize@plt+0x702>
    2979:	81 7d fc ff 0f 00 00 	cmpl   $0xfff,-0x4(%rbp)
    2980:	7e df                	jle    2961 <__cxa_finalize@plt+0x6e1>
    2982:	81 7d fc 00 10 00 00 	cmpl   $0x1000,-0x4(%rbp)
    2989:	75 07                	jne    2992 <__cxa_finalize@plt+0x712>
    298b:	b8 00 00 00 00       	mov    $0x0,%eax
    2990:	eb 69                	jmp    29fb <__cxa_finalize@plt+0x77b>
    2992:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2996:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2999:	89 45 f8             	mov    %eax,-0x8(%rbp)
    299c:	eb 04                	jmp    29a2 <__cxa_finalize@plt+0x722>
    299e:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    29a2:	8b 45 f8             	mov    -0x8(%rbp),%eax
    29a5:	48 63 d0             	movslq %eax,%rdx
    29a8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29ac:	48 01 d0             	add    %rdx,%rax
    29af:	0f b6 00             	movzbl (%rax),%eax
    29b2:	84 c0                	test   %al,%al
    29b4:	74 09                	je     29bf <__cxa_finalize@plt+0x73f>
    29b6:	81 7d f8 ff 0f 00 00 	cmpl   $0xfff,-0x8(%rbp)
    29bd:	7e df                	jle    299e <__cxa_finalize@plt+0x71e>
    29bf:	8b 45 f8             	mov    -0x8(%rbp),%eax
    29c2:	2b 45 fc             	sub    -0x4(%rbp),%eax
    29c5:	48 63 d0             	movslq %eax,%rdx
    29c8:	8b 45 fc             	mov    -0x4(%rbp),%eax
    29cb:	48 63 c8             	movslq %eax,%rcx
    29ce:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    29d2:	48 01 c1             	add    %rax,%rcx
    29d5:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    29d9:	48 89 ce             	mov    %rcx,%rsi
    29dc:	48 89 c7             	mov    %rax,%rdi
    29df:	e8 bc f7 ff ff       	call   21a0 <memcpy@plt>
    29e4:	8b 45 f8             	mov    -0x8(%rbp),%eax
    29e7:	2b 45 fc             	sub    -0x4(%rbp),%eax
    29ea:	48 63 d0             	movslq %eax,%rdx
    29ed:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    29f1:	48 01 d0             	add    %rdx,%rax
    29f4:	c6 00 00             	movb   $0x0,(%rax)
    29f7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    29fb:	c9                   	leave
    29fc:	c3                   	ret
    29fd:	55                   	push   %rbp
    29fe:	48 89 e5             	mov    %rsp,%rbp
    2a01:	48 83 ec 20          	sub    $0x20,%rsp
    2a05:	89 7d ec             	mov    %edi,-0x14(%rbp)
    2a08:	8b 45 ec             	mov    -0x14(%rbp),%eax
    2a0b:	89 c7                	mov    %eax,%edi
    2a0d:	e8 1e f7 ff ff       	call   2130 <htonl@plt>
    2a12:	89 45 fc             	mov    %eax,-0x4(%rbp)
    2a15:	48 8d 45 fc          	lea    -0x4(%rbp),%rax
    2a19:	8b 38                	mov    (%rax),%edi
    2a1b:	e8 a0 f6 ff ff       	call   20c0 <inet_ntoa@plt>
    2a20:	c9                   	leave
    2a21:	c3                   	ret
    2a22:	55                   	push   %rbp
    2a23:	48 89 e5             	mov    %rsp,%rbp
    2a26:	48 83 ec 10          	sub    $0x10,%rsp
    2a2a:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
    2a2e:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    2a32:	48 8d 15 67 16 00 00 	lea    0x1667(%rip),%rdx        # 40a0 <__cxa_finalize@plt+0x1e20>
    2a39:	48 89 d6             	mov    %rdx,%rsi
    2a3c:	48 89 c7             	mov    %rax,%rdi
    2a3f:	e8 3c f7 ff ff       	call   2180 <strcmp@plt>
    2a44:	85 c0                	test   %eax,%eax
    2a46:	75 07                	jne    2a4f <__cxa_finalize@plt+0x7cf>
    2a48:	b8 01 00 00 00       	mov    $0x1,%eax
    2a4d:	eb 05                	jmp    2a54 <__cxa_finalize@plt+0x7d4>
    2a4f:	b8 00 00 00 00       	mov    $0x0,%eax
    2a54:	c9                   	leave
    2a55:	c3                   	ret
    2a56:	55                   	push   %rbp
    2a57:	48 89 e5             	mov    %rsp,%rbp
    2a5a:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    2a5e:	89 75 e4             	mov    %esi,-0x1c(%rbp)
    2a61:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    2a68:	e9 f9 00 00 00       	jmp    2b66 <__cxa_finalize@plt+0x8e6>
    2a6d:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    2a74:	eb 79                	jmp    2aef <__cxa_finalize@plt+0x86f>
    2a76:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2a79:	48 98                	cltq
    2a7b:	48 c1 e0 04          	shl    $0x4,%rax
    2a7f:	48 89 c2             	mov    %rax,%rdx
    2a82:	48 8d 05 97 35 00 00 	lea    0x3597(%rip),%rax        # 6020 <__cxa_finalize@plt+0x3da0>
    2a89:	48 8b 14 02          	mov    (%rdx,%rax,1),%rdx
    2a8d:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2a90:	48 98                	cltq
    2a92:	48 01 d0             	add    %rdx,%rax
    2a95:	0f b6 10             	movzbl (%rax),%edx
    2a98:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2a9b:	48 63 c8             	movslq %eax,%rcx
    2a9e:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    2aa2:	48 01 c8             	add    %rcx,%rax
    2aa5:	0f b6 00             	movzbl (%rax),%eax
    2aa8:	38 c2                	cmp    %al,%dl
    2aaa:	74 3f                	je     2aeb <__cxa_finalize@plt+0x86b>
    2aac:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2aaf:	48 98                	cltq
    2ab1:	48 c1 e0 04          	shl    $0x4,%rax
    2ab5:	48 89 c2             	mov    %rax,%rdx
    2ab8:	48 8d 05 61 35 00 00 	lea    0x3561(%rip),%rax        # 6020 <__cxa_finalize@plt+0x3da0>
    2abf:	48 8b 14 02          	mov    (%rdx,%rax,1),%rdx
    2ac3:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2ac6:	48 98                	cltq
    2ac8:	48 01 d0             	add    %rdx,%rax
    2acb:	0f b6 00             	movzbl (%rax),%eax
    2ace:	0f be c0             	movsbl %al,%eax
    2ad1:	8b 55 f8             	mov    -0x8(%rbp),%edx
    2ad4:	48 63 ca             	movslq %edx,%rcx
    2ad7:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    2adb:	48 01 ca             	add    %rcx,%rdx
    2ade:	0f b6 12             	movzbl (%rdx),%edx
    2ae1:	0f be d2             	movsbl %dl,%edx
    2ae4:	83 ea 20             	sub    $0x20,%edx
    2ae7:	39 d0                	cmp    %edx,%eax
    2ae9:	75 38                	jne    2b23 <__cxa_finalize@plt+0x8a3>
    2aeb:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
    2aef:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2af2:	48 98                	cltq
    2af4:	48 c1 e0 04          	shl    $0x4,%rax
    2af8:	48 89 c2             	mov    %rax,%rdx
    2afb:	48 8d 05 1e 35 00 00 	lea    0x351e(%rip),%rax        # 6020 <__cxa_finalize@plt+0x3da0>
    2b02:	48 8b 14 02          	mov    (%rdx,%rax,1),%rdx
    2b06:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2b09:	48 98                	cltq
    2b0b:	48 01 d0             	add    %rdx,%rax
    2b0e:	0f b6 00             	movzbl (%rax),%eax
    2b11:	84 c0                	test   %al,%al
    2b13:	74 0f                	je     2b24 <__cxa_finalize@plt+0x8a4>
    2b15:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2b18:	3b 45 e4             	cmp    -0x1c(%rbp),%eax
    2b1b:	0f 8c 55 ff ff ff    	jl     2a76 <__cxa_finalize@plt+0x7f6>
    2b21:	eb 01                	jmp    2b24 <__cxa_finalize@plt+0x8a4>
    2b23:	90                   	nop
    2b24:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2b27:	48 98                	cltq
    2b29:	48 c1 e0 04          	shl    $0x4,%rax
    2b2d:	48 89 c2             	mov    %rax,%rdx
    2b30:	48 8d 05 e9 34 00 00 	lea    0x34e9(%rip),%rax        # 6020 <__cxa_finalize@plt+0x3da0>
    2b37:	48 8b 14 02          	mov    (%rdx,%rax,1),%rdx
    2b3b:	8b 45 f8             	mov    -0x8(%rbp),%eax
    2b3e:	48 98                	cltq
    2b40:	48 01 d0             	add    %rdx,%rax
    2b43:	0f b6 00             	movzbl (%rax),%eax
    2b46:	84 c0                	test   %al,%al
    2b48:	75 18                	jne    2b62 <__cxa_finalize@plt+0x8e2>
    2b4a:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2b4d:	48 98                	cltq
    2b4f:	48 c1 e0 04          	shl    $0x4,%rax
    2b53:	48 89 c2             	mov    %rax,%rdx
    2b56:	48 8d 05 cb 34 00 00 	lea    0x34cb(%rip),%rax        # 6028 <__cxa_finalize@plt+0x3da8>
    2b5d:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    2b60:	eb 13                	jmp    2b75 <__cxa_finalize@plt+0x8f5>
    2b62:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2b66:	83 7d fc 1d          	cmpl   $0x1d,-0x4(%rbp)
    2b6a:	0f 8e fd fe ff ff    	jle    2a6d <__cxa_finalize@plt+0x7ed>
    2b70:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
    2b75:	5d                   	pop    %rbp
    2b76:	c3                   	ret
    2b77:	55                   	push   %rbp
    2b78:	48 89 e5             	mov    %rsp,%rbp
    2b7b:	48 81 ec 50 55 00 00 	sub    $0x5550,%rsp
    2b82:	be dc 00 00 00       	mov    $0xdc,%esi
    2b87:	48 8d 05 15 15 00 00 	lea    0x1515(%rip),%rax        # 40a3 <__cxa_finalize@plt+0x1e23>
    2b8e:	48 89 c7             	mov    %rax,%rdi
    2b91:	b8 00 00 00 00       	mov    $0x0,%eax
    2b96:	e8 de f7 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2b9b:	48 c7 85 a0 ef ff ff 	movq   $0x0,-0x1060(%rbp)
    2ba2:	00 00 00 00 
    2ba6:	48 c7 85 a8 ef ff ff 	movq   $0x0,-0x1058(%rbp)
    2bad:	00 00 00 00 
    2bb1:	48 8d 95 b0 ef ff ff 	lea    -0x1050(%rbp),%rdx
    2bb8:	b8 00 00 00 00       	mov    $0x0,%eax
    2bbd:	b9 fe 01 00 00       	mov    $0x1fe,%ecx
    2bc2:	48 89 d7             	mov    %rdx,%rdi
    2bc5:	f3 48 ab             	rep stos %rax,(%rdi)
    2bc8:	48 c7 85 a0 df ff ff 	movq   $0x0,-0x2060(%rbp)
    2bcf:	00 00 00 00 
    2bd3:	48 c7 85 a8 df ff ff 	movq   $0x0,-0x2058(%rbp)
    2bda:	00 00 00 00 
    2bde:	48 8d 95 b0 df ff ff 	lea    -0x2050(%rbp),%rdx
    2be5:	b8 00 00 00 00       	mov    $0x0,%eax
    2bea:	b9 fe 01 00 00       	mov    $0x1fe,%ecx
    2bef:	48 89 d7             	mov    %rdx,%rdi
    2bf2:	f3 48 ab             	rep stos %rax,(%rdi)
    2bf5:	c7 45 f8 02 00 00 00 	movl   $0x2,-0x8(%rbp)
    2bfc:	bf 00 00 00 00       	mov    $0x0,%edi
    2c01:	e8 aa f5 ff ff       	call   21b0 <time@plt>
    2c06:	89 c7                	mov    %eax,%edi
    2c08:	e8 63 f5 ff ff       	call   2170 <srand@plt>
    2c0d:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%rbp)
    2c14:	c7 45 f0 ff ff ff ff 	movl   $0xffffffff,-0x10(%rbp)
    2c1b:	c7 85 9c df ff ff 00 	movl   $0x0,-0x2064(%rbp)
    2c22:	00 00 00 
    2c25:	c7 85 8c cf ff ff 00 	movl   $0x0,-0x3074(%rbp)
    2c2c:	00 00 00 
    2c2f:	66 c7 85 8a cf ff ff 	movw   $0x0,-0x3076(%rbp)
    2c36:	00 00 
    2c38:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    2c3f:	00 
    2c40:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    2c47:	c7 45 d0 01 00 00 00 	movl   $0x1,-0x30(%rbp)
    2c4e:	c7 45 cc 00 00 00 00 	movl   $0x0,-0x34(%rbp)
    2c55:	e9 76 0d 00 00       	jmp    39d0 <__cxa_finalize@plt+0x1750>
    2c5a:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    2c5e:	0f 84 94 0d 00 00    	je     39f8 <__cxa_finalize@plt+0x1778>
    2c64:	8b 45 c8             	mov    -0x38(%rbp),%eax
    2c67:	48 98                	cltq
    2c69:	48 8d 15 b0 35 00 00 	lea    0x35b0(%rip),%rdx        # 6220 <__cxa_finalize@plt+0x3fa0>
    2c70:	c6 04 10 00          	movb   $0x0,(%rax,%rdx,1)
    2c74:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    2c7b:	eb 3c                	jmp    2cb9 <__cxa_finalize@plt+0xa39>
    2c7d:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2c80:	48 98                	cltq
    2c82:	48 8d 15 97 35 00 00 	lea    0x3597(%rip),%rdx        # 6220 <__cxa_finalize@plt+0x3fa0>
    2c89:	0f b6 04 10          	movzbl (%rax,%rdx,1),%eax
    2c8d:	3c 0d                	cmp    $0xd,%al
    2c8f:	74 14                	je     2ca5 <__cxa_finalize@plt+0xa25>
    2c91:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2c94:	48 98                	cltq
    2c96:	48 8d 15 83 35 00 00 	lea    0x3583(%rip),%rdx        # 6220 <__cxa_finalize@plt+0x3fa0>
    2c9d:	0f b6 04 10          	movzbl (%rax,%rdx,1),%eax
    2ca1:	3c 0a                	cmp    $0xa,%al
    2ca3:	75 10                	jne    2cb5 <__cxa_finalize@plt+0xa35>
    2ca5:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2ca8:	48 98                	cltq
    2caa:	48 8d 15 6f 35 00 00 	lea    0x356f(%rip),%rdx        # 6220 <__cxa_finalize@plt+0x3fa0>
    2cb1:	c6 04 10 00          	movb   $0x0,(%rax,%rdx,1)
    2cb5:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    2cb9:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2cbc:	3b 45 c8             	cmp    -0x38(%rbp),%eax
    2cbf:	7c bc                	jl     2c7d <__cxa_finalize@plt+0x9fd>
    2cc1:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2cc4:	48 98                	cltq
    2cc6:	48 8d 15 53 35 00 00 	lea    0x3553(%rip),%rdx        # 6220 <__cxa_finalize@plt+0x3fa0>
    2ccd:	0f b6 04 10          	movzbl (%rax,%rdx,1),%eax
    2cd1:	84 c0                	test   %al,%al
    2cd3:	0f 85 22 0d 00 00    	jne    39fb <__cxa_finalize@plt+0x177b>
    2cd9:	8b 45 fc             	mov    -0x4(%rbp),%eax
    2cdc:	89 45 c8             	mov    %eax,-0x38(%rbp)
    2cdf:	8b 45 c8             	mov    -0x38(%rbp),%eax
    2ce2:	89 c6                	mov    %eax,%esi
    2ce4:	48 8d 05 35 35 00 00 	lea    0x3535(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    2ceb:	48 89 c7             	mov    %rax,%rdi
    2cee:	e8 63 fd ff ff       	call   2a56 <__cxa_finalize@plt+0x7d6>
    2cf3:	89 45 c4             	mov    %eax,-0x3c(%rbp)
    2cf6:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    2cfa:	79 18                	jns    2d14 <__cxa_finalize@plt+0xa94>
    2cfc:	8b 45 c8             	mov    -0x38(%rbp),%eax
    2cff:	83 e8 02             	sub    $0x2,%eax
    2d02:	48 98                	cltq
    2d04:	48 8d 15 15 35 00 00 	lea    0x3515(%rip),%rdx        # 6220 <__cxa_finalize@plt+0x3fa0>
    2d0b:	c6 04 10 00          	movb   $0x0,(%rax,%rdx,1)
    2d0f:	e9 bc 0c 00 00       	jmp    39d0 <__cxa_finalize@plt+0x1750>
    2d14:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    2d18:	75 0c                	jne    2d26 <__cxa_finalize@plt+0xaa6>
    2d1a:	83 7d c4 00          	cmpl   $0x0,-0x3c(%rbp)
    2d1e:	74 06                	je     2d26 <__cxa_finalize@plt+0xaa6>
    2d20:	83 7d c4 1a          	cmpl   $0x1a,-0x3c(%rbp)
    2d24:	75 12                	jne    2d38 <__cxa_finalize@plt+0xab8>
    2d26:	83 7d d4 01          	cmpl   $0x1,-0x2c(%rbp)
    2d2a:	75 2a                	jne    2d56 <__cxa_finalize@plt+0xad6>
    2d2c:	83 7d c4 01          	cmpl   $0x1,-0x3c(%rbp)
    2d30:	74 24                	je     2d56 <__cxa_finalize@plt+0xad6>
    2d32:	83 7d c4 1a          	cmpl   $0x1a,-0x3c(%rbp)
    2d36:	74 1e                	je     2d56 <__cxa_finalize@plt+0xad6>
    2d38:	be 12 02 00 00       	mov    $0x212,%esi
    2d3d:	48 8d 05 74 13 00 00 	lea    0x1374(%rip),%rax        # 40b8 <__cxa_finalize@plt+0x1e38>
    2d44:	48 89 c7             	mov    %rax,%rdi
    2d47:	b8 00 00 00 00       	mov    $0x0,%eax
    2d4c:	e8 28 f6 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2d51:	e9 59 0c 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2d56:	83 7d c4 1d          	cmpl   $0x1d,-0x3c(%rbp)
    2d5a:	0f 87 2d 0c 00 00    	ja     398d <__cxa_finalize@plt+0x170d>
    2d60:	8b 45 c4             	mov    -0x3c(%rbp),%eax
    2d63:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
    2d6a:	00 
    2d6b:	48 8d 05 86 17 00 00 	lea    0x1786(%rip),%rax        # 44f8 <__cxa_finalize@plt+0x2278>
    2d72:	8b 04 02             	mov    (%rdx,%rax,1),%eax
    2d75:	48 98                	cltq
    2d77:	48 8d 15 7a 17 00 00 	lea    0x177a(%rip),%rdx        # 44f8 <__cxa_finalize@plt+0x2278>
    2d7e:	48 01 d0             	add    %rdx,%rax
    2d81:	ff e0                	jmp    *%rax
    2d83:	be c8 00 00 00       	mov    $0xc8,%esi
    2d88:	48 8d 05 48 13 00 00 	lea    0x1348(%rip),%rax        # 40d7 <__cxa_finalize@plt+0x1e57>
    2d8f:	48 89 c7             	mov    %rax,%rdi
    2d92:	b8 00 00 00 00       	mov    $0x0,%eax
    2d97:	e8 dd f5 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2d9c:	e9 0e 0c 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2da1:	be dd 00 00 00       	mov    $0xdd,%esi
    2da6:	48 8d 05 33 13 00 00 	lea    0x1333(%rip),%rax        # 40e0 <__cxa_finalize@plt+0x1e60>
    2dad:	48 89 c7             	mov    %rax,%rdi
    2db0:	b8 00 00 00 00       	mov    $0x0,%eax
    2db5:	e8 bf f5 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2dba:	c7 45 d0 00 00 00 00 	movl   $0x0,-0x30(%rbp)
    2dc1:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    2dc8:	e9 e2 0b 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2dcd:	be c8 00 00 00       	mov    $0xc8,%esi
    2dd2:	48 8d 05 1a 13 00 00 	lea    0x131a(%rip),%rax        # 40f3 <__cxa_finalize@plt+0x1e73>
    2dd9:	48 89 c7             	mov    %rax,%rdi
    2ddc:	b8 00 00 00 00       	mov    $0x0,%eax
    2de1:	e8 93 f5 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2de6:	e9 c4 0b 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2deb:	48 8d 05 2e 34 00 00 	lea    0x342e(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    2df2:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    2df6:	eb 05                	jmp    2dfd <__cxa_finalize@plt+0xb7d>
    2df8:	48 83 45 e0 01       	addq   $0x1,-0x20(%rbp)
    2dfd:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2e01:	48 83 e8 01          	sub    $0x1,%rax
    2e05:	0f b6 00             	movzbl (%rax),%eax
    2e08:	3c 20                	cmp    $0x20,%al
    2e0a:	75 ec                	jne    2df8 <__cxa_finalize@plt+0xb78>
    2e0c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2e10:	48 89 c7             	mov    %rax,%rdi
    2e13:	e8 0a fc ff ff       	call   2a22 <__cxa_finalize@plt+0x7a2>
    2e18:	85 c0                	test   %eax,%eax
    2e1a:	74 25                	je     2e41 <__cxa_finalize@plt+0xbc1>
    2e1c:	be 4b 01 00 00       	mov    $0x14b,%esi
    2e21:	48 8d 05 e0 12 00 00 	lea    0x12e0(%rip),%rax        # 4108 <__cxa_finalize@plt+0x1e88>
    2e28:	48 89 c7             	mov    %rax,%rdi
    2e2b:	b8 00 00 00 00       	mov    $0x0,%eax
    2e30:	e8 44 f5 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2e35:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%rbp)
    2e3c:	e9 6e 0b 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2e41:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2e45:	48 89 c7             	mov    %rax,%rdi
    2e48:	e8 a3 f3 ff ff       	call   21f0 <getspnam@plt>
    2e4d:	48 89 45 a0          	mov    %rax,-0x60(%rbp)
    2e51:	48 83 7d a0 00       	cmpq   $0x0,-0x60(%rbp)
    2e56:	74 25                	je     2e7d <__cxa_finalize@plt+0xbfd>
    2e58:	be 4b 01 00 00       	mov    $0x14b,%esi
    2e5d:	48 8d 05 a4 12 00 00 	lea    0x12a4(%rip),%rax        # 4108 <__cxa_finalize@plt+0x1e88>
    2e64:	48 89 c7             	mov    %rax,%rdi
    2e67:	b8 00 00 00 00       	mov    $0x0,%eax
    2e6c:	e8 08 f5 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2e71:	c7 45 d4 01 00 00 00 	movl   $0x1,-0x2c(%rbp)
    2e78:	e9 32 0b 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2e7d:	be 12 02 00 00       	mov    $0x212,%esi
    2e82:	48 8d 05 a7 12 00 00 	lea    0x12a7(%rip),%rax        # 4130 <__cxa_finalize@plt+0x1eb0>
    2e89:	48 89 c7             	mov    %rax,%rdi
    2e8c:	b8 00 00 00 00       	mov    $0x0,%eax
    2e91:	e8 e3 f4 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2e96:	e9 14 0b 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2e9b:	48 8d 05 7e 33 00 00 	lea    0x337e(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    2ea2:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    2ea6:	eb 05                	jmp    2ead <__cxa_finalize@plt+0xc2d>
    2ea8:	48 83 45 d8 01       	addq   $0x1,-0x28(%rbp)
    2ead:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    2eb1:	48 83 e8 01          	sub    $0x1,%rax
    2eb5:	0f b6 00             	movzbl (%rax),%eax
    2eb8:	3c 20                	cmp    $0x20,%al
    2eba:	75 ec                	jne    2ea8 <__cxa_finalize@plt+0xc28>
    2ebc:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    2ec0:	48 89 c7             	mov    %rax,%rdi
    2ec3:	e8 5a fb ff ff       	call   2a22 <__cxa_finalize@plt+0x7a2>
    2ec8:	85 c0                	test   %eax,%eax
    2eca:	74 25                	je     2ef1 <__cxa_finalize@plt+0xc71>
    2ecc:	be e6 00 00 00       	mov    $0xe6,%esi
    2ed1:	48 8d 05 89 12 00 00 	lea    0x1289(%rip),%rax        # 4161 <__cxa_finalize@plt+0x1ee1>
    2ed8:	48 89 c7             	mov    %rax,%rdi
    2edb:	b8 00 00 00 00       	mov    $0x0,%eax
    2ee0:	e8 94 f4 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2ee5:	c7 45 d4 02 00 00 00 	movl   $0x2,-0x2c(%rbp)
    2eec:	e9 be 0a 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2ef1:	c7 45 ac 00 00 00 00 	movl   $0x0,-0x54(%rbp)
    2ef8:	be 12 02 00 00       	mov    $0x212,%esi
    2efd:	48 8d 05 7c 12 00 00 	lea    0x127c(%rip),%rax        # 4180 <__cxa_finalize@plt+0x1f00>
    2f04:	48 89 c7             	mov    %rax,%rdi
    2f07:	b8 00 00 00 00       	mov    $0x0,%eax
    2f0c:	e8 68 f4 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2f11:	c7 45 d4 00 00 00 00 	movl   $0x0,-0x2c(%rbp)
    2f18:	e9 92 0a 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2f1d:	48 8d 85 a0 ef ff ff 	lea    -0x1060(%rbp),%rax
    2f24:	be 00 10 00 00       	mov    $0x1000,%esi
    2f29:	48 89 c7             	mov    %rax,%rdi
    2f2c:	e8 1f f2 ff ff       	call   2150 <getcwd@plt>
    2f31:	48 8d 85 a0 ef ff ff 	lea    -0x1060(%rbp),%rax
    2f38:	48 89 c2             	mov    %rax,%rdx
    2f3b:	be 01 01 00 00       	mov    $0x101,%esi
    2f40:	48 8d 05 64 12 00 00 	lea    0x1264(%rip),%rax        # 41ab <__cxa_finalize@plt+0x1f2b>
    2f47:	48 89 c7             	mov    %rax,%rdi
    2f4a:	b8 00 00 00 00       	mov    $0x0,%eax
    2f4f:	e8 25 f4 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2f54:	e9 56 0a 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2f59:	be d7 00 00 00       	mov    $0xd7,%esi
    2f5e:	48 8d 05 51 12 00 00 	lea    0x1251(%rip),%rax        # 41b6 <__cxa_finalize@plt+0x1f36>
    2f65:	48 89 c7             	mov    %rax,%rdi
    2f68:	b8 00 00 00 00       	mov    $0x0,%eax
    2f6d:	e8 07 f4 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2f72:	e9 38 0a 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2f77:	0f b6 05 a7 32 00 00 	movzbl 0x32a7(%rip),%eax        # 6225 <__cxa_finalize@plt+0x3fa5>
    2f7e:	3c 41                	cmp    $0x41,%al
    2f80:	75 31                	jne    2fb3 <__cxa_finalize@plt+0xd33>
    2f82:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    2f89:	0f b6 05 95 32 00 00 	movzbl 0x3295(%rip),%eax        # 6225 <__cxa_finalize@plt+0x3fa5>
    2f90:	0f be c0             	movsbl %al,%eax
    2f93:	89 c2                	mov    %eax,%edx
    2f95:	be c8 00 00 00       	mov    $0xc8,%esi
    2f9a:	48 8d 05 20 12 00 00 	lea    0x1220(%rip),%rax        # 41c1 <__cxa_finalize@plt+0x1f41>
    2fa1:	48 89 c7             	mov    %rax,%rdi
    2fa4:	b8 00 00 00 00       	mov    $0x0,%eax
    2fa9:	e8 cb f3 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2fae:	e9 fc 09 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2fb3:	0f b6 05 6b 32 00 00 	movzbl 0x326b(%rip),%eax        # 6225 <__cxa_finalize@plt+0x3fa5>
    2fba:	3c 49                	cmp    $0x49,%al
    2fbc:	75 31                	jne    2fef <__cxa_finalize@plt+0xd6f>
    2fbe:	c7 45 f8 02 00 00 00 	movl   $0x2,-0x8(%rbp)
    2fc5:	0f b6 05 59 32 00 00 	movzbl 0x3259(%rip),%eax        # 6225 <__cxa_finalize@plt+0x3fa5>
    2fcc:	0f be c0             	movsbl %al,%eax
    2fcf:	89 c2                	mov    %eax,%edx
    2fd1:	be c8 00 00 00       	mov    $0xc8,%esi
    2fd6:	48 8d 05 e4 11 00 00 	lea    0x11e4(%rip),%rax        # 41c1 <__cxa_finalize@plt+0x1f41>
    2fdd:	48 89 c7             	mov    %rax,%rdi
    2fe0:	b8 00 00 00 00       	mov    $0x0,%eax
    2fe5:	e8 8f f3 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    2fea:	e9 c0 09 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    2fef:	83 7d f8 00          	cmpl   $0x0,-0x8(%rbp)
    2ff3:	75 07                	jne    2ffc <__cxa_finalize@plt+0xd7c>
    2ff5:	b8 41 00 00 00       	mov    $0x41,%eax
    2ffa:	eb 05                	jmp    3001 <__cxa_finalize@plt+0xd81>
    2ffc:	b8 49 00 00 00       	mov    $0x49,%eax
    3001:	89 c2                	mov    %eax,%edx
    3003:	be f4 01 00 00       	mov    $0x1f4,%esi
    3008:	48 8d 05 d1 11 00 00 	lea    0x11d1(%rip),%rax        # 41e0 <__cxa_finalize@plt+0x1f60>
    300f:	48 89 c7             	mov    %rax,%rdi
    3012:	b8 00 00 00 00       	mov    $0x0,%eax
    3017:	e8 5d f3 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    301c:	e9 8e 09 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3021:	48 8d 95 8a cf ff ff 	lea    -0x3076(%rbp),%rdx
    3028:	48 8d 85 8c cf ff ff 	lea    -0x3074(%rbp),%rax
    302f:	48 89 c6             	mov    %rax,%rsi
    3032:	48 8d 05 e7 31 00 00 	lea    0x31e7(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    3039:	48 89 c7             	mov    %rax,%rdi
    303c:	e8 2a f7 ff ff       	call   276b <__cxa_finalize@plt+0x4eb>
    3041:	89 45 cc             	mov    %eax,-0x34(%rbp)
    3044:	83 7d cc 00          	cmpl   $0x0,-0x34(%rbp)
    3048:	75 1e                	jne    3068 <__cxa_finalize@plt+0xde8>
    304a:	be f5 01 00 00       	mov    $0x1f5,%esi
    304f:	48 8d 05 c2 11 00 00 	lea    0x11c2(%rip),%rax        # 4218 <__cxa_finalize@plt+0x1f98>
    3056:	48 89 c7             	mov    %rax,%rdi
    3059:	b8 00 00 00 00       	mov    $0x0,%eax
    305e:	e8 16 f3 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3063:	e9 47 09 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3068:	be c8 00 00 00       	mov    $0xc8,%esi
    306d:	48 8d 05 cf 11 00 00 	lea    0x11cf(%rip),%rax        # 4243 <__cxa_finalize@plt+0x1fc3>
    3074:	48 89 c7             	mov    %rax,%rdi
    3077:	b8 00 00 00 00       	mov    $0x0,%eax
    307c:	e8 f8 f2 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3081:	e9 29 09 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3086:	83 7d f0 00          	cmpl   $0x0,-0x10(%rbp)
    308a:	0f 88 8e 00 00 00    	js     311e <__cxa_finalize@plt+0xe9e>
    3090:	48 8d 85 a0 ef ff ff 	lea    -0x1060(%rbp),%rax
    3097:	be 00 10 00 00       	mov    $0x1000,%esi
    309c:	48 89 c7             	mov    %rax,%rdi
    309f:	e8 ac f0 ff ff       	call   2150 <getcwd@plt>
    30a4:	48 8d 95 a0 ef ff ff 	lea    -0x1060(%rbp),%rdx
    30ab:	48 8d 85 a0 df ff ff 	lea    -0x2060(%rbp),%rax
    30b2:	48 8d 0d a5 11 00 00 	lea    0x11a5(%rip),%rcx        # 425e <__cxa_finalize@plt+0x1fde>
    30b9:	48 89 ce             	mov    %rcx,%rsi
    30bc:	48 89 c7             	mov    %rax,%rdi
    30bf:	b8 00 00 00 00       	mov    $0x0,%eax
    30c4:	e8 87 f1 ff ff       	call   2250 <sprintf@plt>
    30c9:	48 8d 85 a0 df ff ff 	lea    -0x2060(%rbp),%rax
    30d0:	48 8d 15 90 11 00 00 	lea    0x1190(%rip),%rdx        # 4267 <__cxa_finalize@plt+0x1fe7>
    30d7:	48 89 d6             	mov    %rdx,%rsi
    30da:	48 89 c7             	mov    %rax,%rdi
    30dd:	e8 2e f1 ff ff       	call   2210 <popen@plt>
    30e2:	48 89 45 b8          	mov    %rax,-0x48(%rbp)
    30e6:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    30ea:	48 89 c7             	mov    %rax,%rdi
    30ed:	e8 57 f3 ff ff       	call   2449 <__cxa_finalize@plt+0x1c9>
    30f2:	be e2 00 00 00       	mov    $0xe2,%esi
    30f7:	48 8d 05 6b 11 00 00 	lea    0x116b(%rip),%rax        # 4269 <__cxa_finalize@plt+0x1fe9>
    30fe:	48 89 c7             	mov    %rax,%rdi
    3101:	b8 00 00 00 00       	mov    $0x0,%eax
    3106:	e8 6e f2 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    310b:	48 8b 45 b8          	mov    -0x48(%rbp),%rax
    310f:	48 89 c7             	mov    %rax,%rdi
    3112:	e8 f9 ef ff ff       	call   2110 <pclose@plt>
    3117:	c7 45 f0 ff ff ff ff 	movl   $0xffffffff,-0x10(%rbp)
    311e:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    3122:	0f 88 83 08 00 00    	js     39ab <__cxa_finalize@plt+0x172b>
    3128:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%rbp)
    312f:	e9 77 08 00 00       	jmp    39ab <__cxa_finalize@plt+0x172b>
    3134:	48 8d 85 9c df ff ff 	lea    -0x2064(%rbp),%rax
    313b:	48 89 c6             	mov    %rax,%rsi
    313e:	48 8d 05 db 30 00 00 	lea    0x30db(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    3145:	48 89 c7             	mov    %rax,%rdi
    3148:	e8 e6 f4 ff ff       	call   2633 <__cxa_finalize@plt+0x3b3>
    314d:	85 c0                	test   %eax,%eax
    314f:	75 26                	jne    3177 <__cxa_finalize@plt+0xef7>
    3151:	8b 85 9c df ff ff    	mov    -0x2064(%rbp),%eax
    3157:	89 c2                	mov    %eax,%edx
    3159:	be 5e 01 00 00       	mov    $0x15e,%esi
    315e:	48 8d 05 23 11 00 00 	lea    0x1123(%rip),%rax        # 4288 <__cxa_finalize@plt+0x2008>
    3165:	48 89 c7             	mov    %rax,%rdi
    3168:	b8 00 00 00 00       	mov    $0x0,%eax
    316d:	e8 07 f2 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3172:	e9 38 08 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3177:	48 8d 05 a8 0e 00 00 	lea    0xea8(%rip),%rax        # 4026 <__cxa_finalize@plt+0x1da6>
    317e:	48 89 c2             	mov    %rax,%rdx
    3181:	be f5 01 00 00       	mov    $0x1f5,%esi
    3186:	48 8d 05 34 11 00 00 	lea    0x1134(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    318d:	48 89 c7             	mov    %rax,%rdi
    3190:	b8 00 00 00 00       	mov    $0x0,%eax
    3195:	e8 df f1 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    319a:	e9 10 08 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    319f:	48 8d 05 7a 30 00 00 	lea    0x307a(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    31a6:	48 89 c7             	mov    %rax,%rdi
    31a9:	e8 90 f7 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    31ae:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    31b2:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    31b7:	75 28                	jne    31e1 <__cxa_finalize@plt+0xf61>
    31b9:	48 8d 05 52 0e 00 00 	lea    0xe52(%rip),%rax        # 4012 <__cxa_finalize@plt+0x1d92>
    31c0:	48 89 c2             	mov    %rax,%rdx
    31c3:	be f5 01 00 00       	mov    $0x1f5,%esi
    31c8:	48 8d 05 f2 10 00 00 	lea    0x10f2(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    31cf:	48 89 c7             	mov    %rax,%rdi
    31d2:	b8 00 00 00 00       	mov    $0x0,%eax
    31d7:	e8 9d f1 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    31dc:	e9 ce 07 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    31e1:	8b 95 9c df ff ff    	mov    -0x2064(%rbp),%edx
    31e7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    31eb:	89 d6                	mov    %edx,%esi
    31ed:	48 89 c7             	mov    %rax,%rdi
    31f0:	e8 d9 f2 ff ff       	call   24ce <__cxa_finalize@plt+0x24e>
    31f5:	89 45 b0             	mov    %eax,-0x50(%rbp)
    31f8:	83 7d b0 00          	cmpl   $0x0,-0x50(%rbp)
    31fc:	78 2f                	js     322d <__cxa_finalize@plt+0xfad>
    31fe:	48 8d 05 0d 0e 00 00 	lea    0xe0d(%rip),%rax        # 4012 <__cxa_finalize@plt+0x1d92>
    3205:	48 89 c2             	mov    %rax,%rdx
    3208:	be e2 00 00 00       	mov    $0xe2,%esi
    320d:	48 8d 05 55 10 00 00 	lea    0x1055(%rip),%rax        # 4269 <__cxa_finalize@plt+0x1fe9>
    3214:	48 89 c7             	mov    %rax,%rdi
    3217:	b8 00 00 00 00       	mov    $0x0,%eax
    321c:	e8 58 f1 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3221:	c7 85 9c df ff ff 00 	movl   $0x0,-0x2064(%rbp)
    3228:	00 00 00 
    322b:	eb 50                	jmp    327d <__cxa_finalize@plt+0xffd>
    322d:	83 7d b0 ff          	cmpl   $0xffffffff,-0x50(%rbp)
    3231:	75 27                	jne    325a <__cxa_finalize@plt+0xfda>
    3233:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3237:	be 00 00 00 00       	mov    $0x0,%esi
    323c:	48 89 c7             	mov    %rax,%rdi
    323f:	e8 bc ef ff ff       	call   2200 <access@plt>
    3244:	85 c0                	test   %eax,%eax
    3246:	75 09                	jne    3251 <__cxa_finalize@plt+0xfd1>
    3248:	48 8d 05 91 10 00 00 	lea    0x1091(%rip),%rax        # 42e0 <__cxa_finalize@plt+0x2060>
    324f:	eb 10                	jmp    3261 <__cxa_finalize@plt+0xfe1>
    3251:	48 8d 05 a8 10 00 00 	lea    0x10a8(%rip),%rax        # 4300 <__cxa_finalize@plt+0x2080>
    3258:	eb 07                	jmp    3261 <__cxa_finalize@plt+0xfe1>
    325a:	48 8d 05 ae 10 00 00 	lea    0x10ae(%rip),%rax        # 430f <__cxa_finalize@plt+0x208f>
    3261:	48 89 c2             	mov    %rax,%rdx
    3264:	be f4 01 00 00       	mov    $0x1f4,%esi
    3269:	48 8d 05 ac 10 00 00 	lea    0x10ac(%rip),%rax        # 431c <__cxa_finalize@plt+0x209c>
    3270:	48 89 c7             	mov    %rax,%rdi
    3273:	b8 00 00 00 00       	mov    $0x0,%eax
    3278:	e8 fc f0 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    327d:	83 7d f0 00          	cmpl   $0x0,-0x10(%rbp)
    3281:	78 07                	js     328a <__cxa_finalize@plt+0x100a>
    3283:	c7 45 f0 ff ff ff ff 	movl   $0xffffffff,-0x10(%rbp)
    328a:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    328e:	0f 88 1a 07 00 00    	js     39ae <__cxa_finalize@plt+0x172e>
    3294:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%rbp)
    329b:	e9 0e 07 00 00       	jmp    39ae <__cxa_finalize@plt+0x172e>
    32a0:	48 8d 85 b0 ca ff ff 	lea    -0x3550(%rbp),%rax
    32a7:	ba 4c 04 00 00       	mov    $0x44c,%edx
    32ac:	be 00 00 00 00       	mov    $0x0,%esi
    32b1:	48 89 c7             	mov    %rax,%rdi
    32b4:	e8 87 ee ff ff       	call   2140 <memset@plt>
    32b9:	48 8d 85 b0 ca ff ff 	lea    -0x3550(%rbp),%rax
    32c0:	c7 00 25 64 20 00    	movl   $0x206425,(%rax)
    32c6:	8b 45 c8             	mov    -0x38(%rbp),%eax
    32c9:	48 63 d0             	movslq %eax,%rdx
    32cc:	48 8d 85 b0 ca ff ff 	lea    -0x3550(%rbp),%rax
    32d3:	48 83 c0 03          	add    $0x3,%rax
    32d7:	48 8d 0d 42 2f 00 00 	lea    0x2f42(%rip),%rcx        # 6220 <__cxa_finalize@plt+0x3fa0>
    32de:	48 89 ce             	mov    %rcx,%rsi
    32e1:	48 89 c7             	mov    %rax,%rdi
    32e4:	e8 b7 ee ff ff       	call   21a0 <memcpy@plt>
    32e9:	8b 45 c8             	mov    -0x38(%rbp),%eax
    32ec:	48 98                	cltq
    32ee:	48 8d 50 02          	lea    0x2(%rax),%rdx
    32f2:	48 8d 85 b0 ca ff ff 	lea    -0x3550(%rbp),%rax
    32f9:	48 01 d0             	add    %rdx,%rax
    32fc:	ba 03 00 00 00       	mov    $0x3,%edx
    3301:	48 8d 0d 29 10 00 00 	lea    0x1029(%rip),%rcx        # 4331 <__cxa_finalize@plt+0x20b1>
    3308:	48 89 ce             	mov    %rcx,%rsi
    330b:	48 89 c7             	mov    %rax,%rdi
    330e:	e8 8d ee ff ff       	call   21a0 <memcpy@plt>
    3313:	48 8d 85 b0 ca ff ff 	lea    -0x3550(%rbp),%rax
    331a:	be 20 94 06 00       	mov    $0x69420,%esi
    331f:	48 89 c7             	mov    %rax,%rdi
    3322:	b8 00 00 00 00       	mov    $0x0,%eax
    3327:	e8 4d f0 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    332c:	e9 7e 06 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3331:	48 8d 05 e8 2e 00 00 	lea    0x2ee8(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    3338:	48 89 c7             	mov    %rax,%rdi
    333b:	e8 fe f5 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    3340:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    3344:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3349:	75 28                	jne    3373 <__cxa_finalize@plt+0x10f3>
    334b:	48 8d 05 c0 0c 00 00 	lea    0xcc0(%rip),%rax        # 4012 <__cxa_finalize@plt+0x1d92>
    3352:	48 89 c2             	mov    %rax,%rdx
    3355:	be f5 01 00 00       	mov    $0x1f5,%esi
    335a:	48 8d 05 60 0f 00 00 	lea    0xf60(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    3361:	48 89 c7             	mov    %rax,%rdi
    3364:	b8 00 00 00 00       	mov    $0x0,%eax
    3369:	e8 0b f0 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    336e:	e9 3c 06 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3373:	8b 95 9c df ff ff    	mov    -0x2064(%rbp),%edx
    3379:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    337d:	89 d6                	mov    %edx,%esi
    337f:	48 89 c7             	mov    %rax,%rdi
    3382:	e8 30 f2 ff ff       	call   25b7 <__cxa_finalize@plt+0x337>
    3387:	89 45 b4             	mov    %eax,-0x4c(%rbp)
    338a:	83 7d b4 00          	cmpl   $0x0,-0x4c(%rbp)
    338e:	78 25                	js     33b5 <__cxa_finalize@plt+0x1135>
    3390:	be e2 00 00 00       	mov    $0xe2,%esi
    3395:	48 8d 05 cd 0e 00 00 	lea    0xecd(%rip),%rax        # 4269 <__cxa_finalize@plt+0x1fe9>
    339c:	48 89 c7             	mov    %rax,%rdi
    339f:	b8 00 00 00 00       	mov    $0x0,%eax
    33a4:	e8 d0 ef ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    33a9:	c7 85 9c df ff ff 00 	movl   $0x0,-0x2064(%rbp)
    33b0:	00 00 00 
    33b3:	eb 41                	jmp    33f6 <__cxa_finalize@plt+0x1176>
    33b5:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    33b9:	be 02 00 00 00       	mov    $0x2,%esi
    33be:	48 89 c7             	mov    %rax,%rdi
    33c1:	e8 3a ee ff ff       	call   2200 <access@plt>
    33c6:	85 c0                	test   %eax,%eax
    33c8:	74 09                	je     33d3 <__cxa_finalize@plt+0x1153>
    33ca:	48 8d 05 67 0f 00 00 	lea    0xf67(%rip),%rax        # 4338 <__cxa_finalize@plt+0x20b8>
    33d1:	eb 07                	jmp    33da <__cxa_finalize@plt+0x115a>
    33d3:	48 8d 05 35 0f 00 00 	lea    0xf35(%rip),%rax        # 430f <__cxa_finalize@plt+0x208f>
    33da:	48 89 c2             	mov    %rax,%rdx
    33dd:	be f4 01 00 00       	mov    $0x1f4,%esi
    33e2:	48 8d 05 33 0f 00 00 	lea    0xf33(%rip),%rax        # 431c <__cxa_finalize@plt+0x209c>
    33e9:	48 89 c7             	mov    %rax,%rdi
    33ec:	b8 00 00 00 00       	mov    $0x0,%eax
    33f1:	e8 83 ef ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    33f6:	83 7d f0 00          	cmpl   $0x0,-0x10(%rbp)
    33fa:	78 07                	js     3403 <__cxa_finalize@plt+0x1183>
    33fc:	c7 45 f0 ff ff ff ff 	movl   $0xffffffff,-0x10(%rbp)
    3403:	83 7d f4 00          	cmpl   $0x0,-0xc(%rbp)
    3407:	78 07                	js     3410 <__cxa_finalize@plt+0x1190>
    3409:	c7 45 f4 ff ff ff ff 	movl   $0xffffffff,-0xc(%rbp)
    3410:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3414:	48 89 c7             	mov    %rax,%rdi
    3417:	e8 14 ec ff ff       	call   2030 <free@plt>
    341c:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3423:	00 
    3424:	e9 86 05 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3429:	48 8d 05 28 0f 00 00 	lea    0xf28(%rip),%rax        # 4358 <__cxa_finalize@plt+0x20d8>
    3430:	48 89 c7             	mov    %rax,%rdi
    3433:	e8 c8 ec ff ff       	call   2100 <chdir@plt>
    3438:	85 c0                	test   %eax,%eax
    343a:	75 1e                	jne    345a <__cxa_finalize@plt+0x11da>
    343c:	be fa 00 00 00       	mov    $0xfa,%esi
    3441:	48 8d 05 18 0f 00 00 	lea    0xf18(%rip),%rax        # 4360 <__cxa_finalize@plt+0x20e0>
    3448:	48 89 c7             	mov    %rax,%rdi
    344b:	b8 00 00 00 00       	mov    $0x0,%eax
    3450:	e8 24 ef ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3455:	e9 55 05 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    345a:	48 8d 05 28 0f 00 00 	lea    0xf28(%rip),%rax        # 4389 <__cxa_finalize@plt+0x2109>
    3461:	48 89 c2             	mov    %rax,%rdx
    3464:	be f4 01 00 00       	mov    $0x1f4,%esi
    3469:	48 8d 05 ac 0e 00 00 	lea    0xeac(%rip),%rax        # 431c <__cxa_finalize@plt+0x209c>
    3470:	48 89 c7             	mov    %rax,%rdi
    3473:	b8 00 00 00 00       	mov    $0x0,%eax
    3478:	e8 fc ee ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    347d:	e9 2d 05 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3482:	48 8d 05 97 2d 00 00 	lea    0x2d97(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    3489:	48 89 c7             	mov    %rax,%rdi
    348c:	e8 ad f4 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    3491:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    3495:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    349a:	75 28                	jne    34c4 <__cxa_finalize@plt+0x1244>
    349c:	48 8d 05 a8 0b 00 00 	lea    0xba8(%rip),%rax        # 404b <__cxa_finalize@plt+0x1dcb>
    34a3:	48 89 c2             	mov    %rax,%rdx
    34a6:	be f5 01 00 00       	mov    $0x1f5,%esi
    34ab:	48 8d 05 0f 0e 00 00 	lea    0xe0f(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    34b2:	48 89 c7             	mov    %rax,%rdi
    34b5:	b8 00 00 00 00       	mov    $0x0,%eax
    34ba:	e8 ba ee ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    34bf:	e9 eb 04 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    34c4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    34c8:	48 89 c7             	mov    %rax,%rdi
    34cb:	e8 30 ec ff ff       	call   2100 <chdir@plt>
    34d0:	85 c0                	test   %eax,%eax
    34d2:	75 1b                	jne    34ef <__cxa_finalize@plt+0x126f>
    34d4:	be fa 00 00 00       	mov    $0xfa,%esi
    34d9:	48 8d 05 c5 0e 00 00 	lea    0xec5(%rip),%rax        # 43a5 <__cxa_finalize@plt+0x2125>
    34e0:	48 89 c7             	mov    %rax,%rdi
    34e3:	b8 00 00 00 00       	mov    $0x0,%eax
    34e8:	e8 8c ee ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    34ed:	eb 23                	jmp    3512 <__cxa_finalize@plt+0x1292>
    34ef:	48 8d 05 c1 0e 00 00 	lea    0xec1(%rip),%rax        # 43b7 <__cxa_finalize@plt+0x2137>
    34f6:	48 89 c2             	mov    %rax,%rdx
    34f9:	be f4 01 00 00       	mov    $0x1f4,%esi
    34fe:	48 8d 05 17 0e 00 00 	lea    0xe17(%rip),%rax        # 431c <__cxa_finalize@plt+0x209c>
    3505:	48 89 c7             	mov    %rax,%rdi
    3508:	b8 00 00 00 00       	mov    $0x0,%eax
    350d:	e8 67 ee ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3512:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3516:	48 89 c7             	mov    %rax,%rdi
    3519:	e8 12 eb ff ff       	call   2030 <free@plt>
    351e:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3525:	00 
    3526:	e9 84 04 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    352b:	48 8d 05 ee 2c 00 00 	lea    0x2cee(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    3532:	48 89 c7             	mov    %rax,%rdi
    3535:	e8 04 f4 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    353a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    353e:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3543:	75 56                	jne    359b <__cxa_finalize@plt+0x131b>
    3545:	83 7d c4 1b          	cmpl   $0x1b,-0x3c(%rbp)
    3549:	75 28                	jne    3573 <__cxa_finalize@plt+0x12f3>
    354b:	48 8d 05 39 0b 00 00 	lea    0xb39(%rip),%rax        # 408b <__cxa_finalize@plt+0x1e0b>
    3552:	48 89 c2             	mov    %rax,%rdx
    3555:	be f5 01 00 00       	mov    $0x1f5,%esi
    355a:	48 8d 05 60 0d 00 00 	lea    0xd60(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    3561:	48 89 c7             	mov    %rax,%rdi
    3564:	b8 00 00 00 00       	mov    $0x0,%eax
    3569:	e8 0b ee ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    356e:	e9 3c 04 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3573:	48 8d 05 16 0b 00 00 	lea    0xb16(%rip),%rax        # 4090 <__cxa_finalize@plt+0x1e10>
    357a:	48 89 c2             	mov    %rax,%rdx
    357d:	be f5 01 00 00       	mov    $0x1f5,%esi
    3582:	48 8d 05 38 0d 00 00 	lea    0xd38(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    3589:	48 89 c7             	mov    %rax,%rdi
    358c:	b8 00 00 00 00       	mov    $0x0,%eax
    3591:	e8 e3 ed ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3596:	e9 14 04 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    359b:	48 8d 95 f0 ce ff ff 	lea    -0x3110(%rbp),%rdx
    35a2:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    35a6:	48 89 d6             	mov    %rdx,%rsi
    35a9:	48 89 c7             	mov    %rax,%rdi
    35ac:	e8 df eb ff ff       	call   2190 <stat@plt>
    35b1:	85 c0                	test   %eax,%eax
    35b3:	0f 85 90 00 00 00    	jne    3649 <__cxa_finalize@plt+0x13c9>
    35b9:	83 7d c4 1b          	cmpl   $0x1b,-0x3c(%rbp)
    35bd:	75 67                	jne    3626 <__cxa_finalize@plt+0x13a6>
    35bf:	48 8d 85 b0 ce ff ff 	lea    -0x3150(%rbp),%rax
    35c6:	48 8d 95 f0 ce ff ff 	lea    -0x3110(%rbp),%rdx
    35cd:	48 83 c2 58          	add    $0x58,%rdx
    35d1:	48 89 c6             	mov    %rax,%rsi
    35d4:	48 89 d7             	mov    %rdx,%rdi
    35d7:	e8 44 eb ff ff       	call   2120 <gmtime_r@plt>
    35dc:	48 8d 95 b0 ce ff ff 	lea    -0x3150(%rbp),%rdx
    35e3:	48 8d 85 b0 aa ff ff 	lea    -0x5550(%rbp),%rax
    35ea:	48 89 d1             	mov    %rdx,%rcx
    35ed:	48 8d 15 d5 0d 00 00 	lea    0xdd5(%rip),%rdx        # 43c9 <__cxa_finalize@plt+0x2149>
    35f4:	be 00 10 00 00       	mov    $0x1000,%esi
    35f9:	48 89 c7             	mov    %rax,%rdi
    35fc:	e8 df eb ff ff       	call   21e0 <strftime@plt>
    3601:	48 8d 85 b0 aa ff ff 	lea    -0x5550(%rbp),%rax
    3608:	48 89 c2             	mov    %rax,%rdx
    360b:	be d5 00 00 00       	mov    $0xd5,%esi
    3610:	48 8d 05 bf 0d 00 00 	lea    0xdbf(%rip),%rax        # 43d6 <__cxa_finalize@plt+0x2156>
    3617:	48 89 c7             	mov    %rax,%rdi
    361a:	b8 00 00 00 00       	mov    $0x0,%eax
    361f:	e8 55 ed ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3624:	eb 23                	jmp    3649 <__cxa_finalize@plt+0x13c9>
    3626:	48 8b 85 20 cf ff ff 	mov    -0x30e0(%rbp),%rax
    362d:	48 89 c2             	mov    %rax,%rdx
    3630:	be d5 00 00 00       	mov    $0xd5,%esi
    3635:	48 8d 05 a3 0d 00 00 	lea    0xda3(%rip),%rax        # 43df <__cxa_finalize@plt+0x215f>
    363c:	48 89 c7             	mov    %rax,%rdi
    363f:	b8 00 00 00 00       	mov    $0x0,%eax
    3644:	e8 30 ed ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3649:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    364d:	48 89 c7             	mov    %rax,%rdi
    3650:	e8 db e9 ff ff       	call   2030 <free@plt>
    3655:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    365c:	00 
    365d:	e9 4d 03 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3662:	48 8d 05 b7 2b 00 00 	lea    0x2bb7(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    3669:	48 89 c7             	mov    %rax,%rdi
    366c:	e8 cd f2 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    3671:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    3675:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    367a:	75 25                	jne    36a1 <__cxa_finalize@plt+0x1421>
    367c:	48 8d 05 b7 09 00 00 	lea    0x9b7(%rip),%rax        # 403a <__cxa_finalize@plt+0x1dba>
    3683:	48 89 c2             	mov    %rax,%rdx
    3686:	be f5 01 00 00       	mov    $0x1f5,%esi
    368b:	48 8d 05 2f 0c 00 00 	lea    0xc2f(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    3692:	48 89 c7             	mov    %rax,%rdi
    3695:	b8 00 00 00 00       	mov    $0x0,%eax
    369a:	e8 da ec ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    369f:	eb 4e                	jmp    36ef <__cxa_finalize@plt+0x146f>
    36a1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36a5:	48 89 c7             	mov    %rax,%rdi
    36a8:	e8 93 e9 ff ff       	call   2040 <remove@plt>
    36ad:	85 c0                	test   %eax,%eax
    36af:	75 1b                	jne    36cc <__cxa_finalize@plt+0x144c>
    36b1:	be fa 00 00 00       	mov    $0xfa,%esi
    36b6:	48 8d 05 2b 0d 00 00 	lea    0xd2b(%rip),%rax        # 43e8 <__cxa_finalize@plt+0x2168>
    36bd:	48 89 c7             	mov    %rax,%rdi
    36c0:	b8 00 00 00 00       	mov    $0x0,%eax
    36c5:	e8 af ec ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    36ca:	eb 23                	jmp    36ef <__cxa_finalize@plt+0x146f>
    36cc:	48 8d 05 2d 0d 00 00 	lea    0xd2d(%rip),%rax        # 4400 <__cxa_finalize@plt+0x2180>
    36d3:	48 89 c2             	mov    %rax,%rdx
    36d6:	be f4 01 00 00       	mov    $0x1f4,%esi
    36db:	48 8d 05 3a 0c 00 00 	lea    0xc3a(%rip),%rax        # 431c <__cxa_finalize@plt+0x209c>
    36e2:	48 89 c7             	mov    %rax,%rdi
    36e5:	b8 00 00 00 00       	mov    $0x0,%eax
    36ea:	e8 8a ec ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    36ef:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    36f3:	48 89 c7             	mov    %rax,%rdi
    36f6:	e8 35 e9 ff ff       	call   2030 <free@plt>
    36fb:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3702:	00 
    3703:	e9 a7 02 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3708:	48 8d 05 11 2b 00 00 	lea    0x2b11(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    370f:	48 89 c7             	mov    %rax,%rdi
    3712:	e8 27 f2 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    3717:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    371b:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3720:	75 25                	jne    3747 <__cxa_finalize@plt+0x14c7>
    3722:	48 8d 05 16 09 00 00 	lea    0x916(%rip),%rax        # 403f <__cxa_finalize@plt+0x1dbf>
    3729:	48 89 c2             	mov    %rax,%rdx
    372c:	be f5 01 00 00       	mov    $0x1f5,%esi
    3731:	48 8d 05 89 0b 00 00 	lea    0xb89(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    3738:	48 89 c7             	mov    %rax,%rdi
    373b:	b8 00 00 00 00       	mov    $0x0,%eax
    3740:	e8 34 ec ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3745:	eb 4e                	jmp    3795 <__cxa_finalize@plt+0x1515>
    3747:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    374b:	48 89 c7             	mov    %rax,%rdi
    374e:	e8 8d e9 ff ff       	call   20e0 <rmdir@plt>
    3753:	85 c0                	test   %eax,%eax
    3755:	75 1b                	jne    3772 <__cxa_finalize@plt+0x14f2>
    3757:	be fa 00 00 00       	mov    $0xfa,%esi
    375c:	48 8d 05 85 0c 00 00 	lea    0xc85(%rip),%rax        # 43e8 <__cxa_finalize@plt+0x2168>
    3763:	48 89 c7             	mov    %rax,%rdi
    3766:	b8 00 00 00 00       	mov    $0x0,%eax
    376b:	e8 09 ec ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3770:	eb 23                	jmp    3795 <__cxa_finalize@plt+0x1515>
    3772:	48 8d 05 a7 0c 00 00 	lea    0xca7(%rip),%rax        # 4420 <__cxa_finalize@plt+0x21a0>
    3779:	48 89 c2             	mov    %rax,%rdx
    377c:	be f4 01 00 00       	mov    $0x1f4,%esi
    3781:	48 8d 05 94 0b 00 00 	lea    0xb94(%rip),%rax        # 431c <__cxa_finalize@plt+0x209c>
    3788:	48 89 c7             	mov    %rax,%rdi
    378b:	b8 00 00 00 00       	mov    $0x0,%eax
    3790:	e8 e4 eb ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3795:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3799:	48 89 c7             	mov    %rax,%rdi
    379c:	e8 8f e8 ff ff       	call   2030 <free@plt>
    37a1:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    37a8:	00 
    37a9:	e9 01 02 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    37ae:	48 8d 05 6b 2a 00 00 	lea    0x2a6b(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    37b5:	48 89 c7             	mov    %rax,%rdi
    37b8:	e8 81 f1 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    37bd:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    37c1:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    37c6:	75 25                	jne    37ed <__cxa_finalize@plt+0x156d>
    37c8:	48 8d 05 74 08 00 00 	lea    0x874(%rip),%rax        # 4043 <__cxa_finalize@plt+0x1dc3>
    37cf:	48 89 c2             	mov    %rax,%rdx
    37d2:	be f5 01 00 00       	mov    $0x1f5,%esi
    37d7:	48 8d 05 e3 0a 00 00 	lea    0xae3(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    37de:	48 89 c7             	mov    %rax,%rdi
    37e1:	b8 00 00 00 00       	mov    $0x0,%eax
    37e6:	e8 8e eb ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    37eb:	eb 53                	jmp    3840 <__cxa_finalize@plt+0x15c0>
    37ed:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    37f1:	be ff 01 00 00       	mov    $0x1ff,%esi
    37f6:	48 89 c7             	mov    %rax,%rdi
    37f9:	e8 72 e8 ff ff       	call   2070 <mkdir@plt>
    37fe:	85 c0                	test   %eax,%eax
    3800:	75 1b                	jne    381d <__cxa_finalize@plt+0x159d>
    3802:	be 01 01 00 00       	mov    $0x101,%esi
    3807:	48 8d 05 30 0c 00 00 	lea    0xc30(%rip),%rax        # 443e <__cxa_finalize@plt+0x21be>
    380e:	48 89 c7             	mov    %rax,%rdi
    3811:	b8 00 00 00 00       	mov    $0x0,%eax
    3816:	e8 5e eb ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    381b:	eb 23                	jmp    3840 <__cxa_finalize@plt+0x15c0>
    381d:	48 8d 05 34 0c 00 00 	lea    0xc34(%rip),%rax        # 4458 <__cxa_finalize@plt+0x21d8>
    3824:	48 89 c2             	mov    %rax,%rdx
    3827:	be f4 01 00 00       	mov    $0x1f4,%esi
    382c:	48 8d 05 e9 0a 00 00 	lea    0xae9(%rip),%rax        # 431c <__cxa_finalize@plt+0x209c>
    3833:	48 89 c7             	mov    %rax,%rdi
    3836:	b8 00 00 00 00       	mov    $0x0,%eax
    383b:	e8 39 eb ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3840:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    3844:	48 89 c7             	mov    %rax,%rdi
    3847:	e8 e4 e7 ff ff       	call   2030 <free@plt>
    384c:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    3853:	00 
    3854:	e9 56 01 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    3859:	48 8d 05 c0 29 00 00 	lea    0x29c0(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    3860:	48 89 c7             	mov    %rax,%rdi
    3863:	e8 d6 f0 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    3868:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    386c:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    3871:	75 25                	jne    3898 <__cxa_finalize@plt+0x1618>
    3873:	48 8d 05 b1 07 00 00 	lea    0x7b1(%rip),%rax        # 402b <__cxa_finalize@plt+0x1dab>
    387a:	48 89 c2             	mov    %rax,%rdx
    387d:	be f5 01 00 00       	mov    $0x1f5,%esi
    3882:	48 8d 05 38 0a 00 00 	lea    0xa38(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    3889:	48 89 c7             	mov    %rax,%rdi
    388c:	b8 00 00 00 00       	mov    $0x0,%eax
    3891:	e8 e3 ea ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3896:	eb 2f                	jmp    38c7 <__cxa_finalize@plt+0x1647>
    3898:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    389c:	48 8d 85 90 cf ff ff 	lea    -0x3070(%rbp),%rax
    38a3:	48 89 d6             	mov    %rdx,%rsi
    38a6:	48 89 c7             	mov    %rax,%rdi
    38a9:	e8 b2 e7 ff ff       	call   2060 <strcpy@plt>
    38ae:	be 5e 01 00 00       	mov    $0x15e,%esi
    38b3:	48 8d 05 c6 0b 00 00 	lea    0xbc6(%rip),%rax        # 4480 <__cxa_finalize@plt+0x2200>
    38ba:	48 89 c7             	mov    %rax,%rdi
    38bd:	b8 00 00 00 00       	mov    $0x0,%eax
    38c2:	e8 b2 ea ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    38c7:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    38cb:	48 89 c7             	mov    %rax,%rdi
    38ce:	e8 5d e7 ff ff       	call   2030 <free@plt>
    38d3:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    38da:	00 
    38db:	e9 cf 00 00 00       	jmp    39af <__cxa_finalize@plt+0x172f>
    38e0:	48 8d 05 39 29 00 00 	lea    0x2939(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    38e7:	48 89 c7             	mov    %rax,%rdi
    38ea:	e8 4f f0 ff ff       	call   293e <__cxa_finalize@plt+0x6be>
    38ef:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    38f3:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    38f8:	75 25                	jne    391f <__cxa_finalize@plt+0x169f>
    38fa:	48 8d 05 2f 07 00 00 	lea    0x72f(%rip),%rax        # 4030 <__cxa_finalize@plt+0x1db0>
    3901:	48 89 c2             	mov    %rax,%rdx
    3904:	be f5 01 00 00       	mov    $0x1f5,%esi
    3909:	48 8d 05 b1 09 00 00 	lea    0x9b1(%rip),%rax        # 42c1 <__cxa_finalize@plt+0x2041>
    3910:	48 89 c7             	mov    %rax,%rdi
    3913:	b8 00 00 00 00       	mov    $0x0,%eax
    3918:	e8 5c ea ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    391d:	eb 58                	jmp    3977 <__cxa_finalize@plt+0x16f7>
    391f:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
    3923:	48 8d 85 90 cf ff ff 	lea    -0x3070(%rbp),%rax
    392a:	48 89 d6             	mov    %rdx,%rsi
    392d:	48 89 c7             	mov    %rax,%rdi
    3930:	e8 fb e8 ff ff       	call   2230 <rename@plt>
    3935:	85 c0                	test   %eax,%eax
    3937:	75 1b                	jne    3954 <__cxa_finalize@plt+0x16d4>
    3939:	be fa 00 00 00       	mov    $0xfa,%esi
    393e:	48 8d 05 5b 0b 00 00 	lea    0xb5b(%rip),%rax        # 44a0 <__cxa_finalize@plt+0x2220>
    3945:	48 89 c7             	mov    %rax,%rdi
    3948:	b8 00 00 00 00       	mov    $0x0,%eax
    394d:	e8 27 ea ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3952:	eb 23                	jmp    3977 <__cxa_finalize@plt+0x16f7>
    3954:	48 8d 05 5d 0b 00 00 	lea    0xb5d(%rip),%rax        # 44b8 <__cxa_finalize@plt+0x2238>
    395b:	48 89 c2             	mov    %rax,%rdx
    395e:	be f4 01 00 00       	mov    $0x1f4,%esi
    3963:	48 8d 05 b2 09 00 00 	lea    0x9b2(%rip),%rax        # 431c <__cxa_finalize@plt+0x209c>
    396a:	48 89 c7             	mov    %rax,%rdi
    396d:	b8 00 00 00 00       	mov    $0x0,%eax
    3972:	e8 02 ea ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    3977:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    397b:	48 89 c7             	mov    %rax,%rdi
    397e:	e8 ad e6 ff ff       	call   2030 <free@plt>
    3983:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    398a:	00 
    398b:	eb 22                	jmp    39af <__cxa_finalize@plt+0x172f>
    398d:	be f8 01 00 00       	mov    $0x1f8,%esi
    3992:	48 8d 05 3e 0b 00 00 	lea    0xb3e(%rip),%rax        # 44d7 <__cxa_finalize@plt+0x2257>
    3999:	48 89 c7             	mov    %rax,%rdi
    399c:	b8 00 00 00 00       	mov    $0x0,%eax
    39a1:	e8 d3 e9 ff ff       	call   2379 <__cxa_finalize@plt+0xf9>
    39a6:	eb 07                	jmp    39af <__cxa_finalize@plt+0x172f>
    39a8:	90                   	nop
    39a9:	eb 04                	jmp    39af <__cxa_finalize@plt+0x172f>
    39ab:	90                   	nop
    39ac:	eb 01                	jmp    39af <__cxa_finalize@plt+0x172f>
    39ae:	90                   	nop
    39af:	48 83 7d e8 00       	cmpq   $0x0,-0x18(%rbp)
    39b4:	74 14                	je     39ca <__cxa_finalize@plt+0x174a>
    39b6:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    39ba:	48 89 c7             	mov    %rax,%rdi
    39bd:	e8 6e e6 ff ff       	call   2030 <free@plt>
    39c2:	48 c7 45 e8 00 00 00 	movq   $0x0,-0x18(%rbp)
    39c9:	00 
    39ca:	83 7d d0 00          	cmpl   $0x0,-0x30(%rbp)
    39ce:	74 2e                	je     39fe <__cxa_finalize@plt+0x177e>
    39d0:	ba 00 10 00 00       	mov    $0x1000,%edx
    39d5:	48 8d 05 44 28 00 00 	lea    0x2844(%rip),%rax        # 6220 <__cxa_finalize@plt+0x3fa0>
    39dc:	48 89 c6             	mov    %rax,%rsi
    39df:	bf 00 00 00 00       	mov    $0x0,%edi
    39e4:	e8 77 e7 ff ff       	call   2160 <read@plt>
    39e9:	89 45 c8             	mov    %eax,-0x38(%rbp)
    39ec:	83 7d c8 00          	cmpl   $0x0,-0x38(%rbp)
    39f0:	0f 8f 64 f2 ff ff    	jg     2c5a <__cxa_finalize@plt+0x9da>
    39f6:	eb 07                	jmp    39ff <__cxa_finalize@plt+0x177f>
    39f8:	90                   	nop
    39f9:	eb 04                	jmp    39ff <__cxa_finalize@plt+0x177f>
    39fb:	90                   	nop
    39fc:	eb 01                	jmp    39ff <__cxa_finalize@plt+0x177f>
    39fe:	90                   	nop
    39ff:	90                   	nop
    3a00:	c9                   	leave
    3a01:	c3                   	ret
    3a02:	55                   	push   %rbp
    3a03:	48 89 e5             	mov    %rsp,%rbp
    3a06:	b8 00 00 00 00       	mov    $0x0,%eax
    3a0b:	e8 67 f1 ff ff       	call   2b77 <__cxa_finalize@plt+0x8f7>
    3a10:	48 8d 05 59 0b 00 00 	lea    0xb59(%rip),%rax        # 4570 <__cxa_finalize@plt+0x22f0>
    3a17:	48 89 c7             	mov    %rax,%rdi
    3a1a:	e8 61 e6 ff ff       	call   2080 <puts@plt>
    3a1f:	bf 00 00 00 00       	mov    $0x0,%edi
    3a24:	e8 27 e6 ff ff       	call   2050 <_exit@plt>
    3a29:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    3a30:	41 57                	push   %r15
    3a32:	4c 8d 3d 5f 22 00 00 	lea    0x225f(%rip),%r15        # 5c98 <__cxa_finalize@plt+0x3a18>
    3a39:	41 56                	push   %r14
    3a3b:	49 89 d6             	mov    %rdx,%r14
    3a3e:	41 55                	push   %r13
    3a40:	49 89 f5             	mov    %rsi,%r13
    3a43:	41 54                	push   %r12
    3a45:	41 89 fc             	mov    %edi,%r12d
    3a48:	55                   	push   %rbp
    3a49:	48 8d 2d 50 22 00 00 	lea    0x2250(%rip),%rbp        # 5ca0 <__cxa_finalize@plt+0x3a20>
    3a50:	53                   	push   %rbx
    3a51:	4c 29 fd             	sub    %r15,%rbp
    3a54:	48 83 ec 08          	sub    $0x8,%rsp
    3a58:	e8 a3 e5 ff ff       	call   2000 <free@plt-0x30>
    3a5d:	48 c1 fd 03          	sar    $0x3,%rbp
    3a61:	74 1b                	je     3a7e <__cxa_finalize@plt+0x17fe>
    3a63:	31 db                	xor    %ebx,%ebx
    3a65:	0f 1f 00             	nopl   (%rax)
    3a68:	4c 89 f2             	mov    %r14,%rdx
    3a6b:	4c 89 ee             	mov    %r13,%rsi
    3a6e:	44 89 e7             	mov    %r12d,%edi
    3a71:	41 ff 14 df          	call   *(%r15,%rbx,8)
    3a75:	48 83 c3 01          	add    $0x1,%rbx
    3a79:	48 39 dd             	cmp    %rbx,%rbp
    3a7c:	75 ea                	jne    3a68 <__cxa_finalize@plt+0x17e8>
    3a7e:	48 83 c4 08          	add    $0x8,%rsp
    3a82:	5b                   	pop    %rbx
    3a83:	5d                   	pop    %rbp
    3a84:	41 5c                	pop    %r12
    3a86:	41 5d                	pop    %r13
    3a88:	41 5e                	pop    %r14
    3a8a:	41 5f                	pop    %r15
    3a8c:	c3                   	ret
    3a8d:	0f 1f 00             	nopl   (%rax)
    3a90:	c3                   	ret

Disassembly of section .fini:

0000000000003a94 <.fini>:
    3a94:	48 83 ec 08          	sub    $0x8,%rsp
    3a98:	48 83 c4 08          	add    $0x8,%rsp
    3a9c:	c3                   	ret
