---
layout: post
title:  "m0leCon CTF 2020 - The Rickshank Rickdemption"
date:   2020-11-15 22:00
categories: [m0leconCTF2020]
tags: [Reverse]
author: jbz
---

The chall was a RPG Pokemon-like client-only game.
The objectives are:
 - Kill all the Mortys (but sadly every Morty is stronger than you)
 - Find the flag

The first thing you can notice is the save function, that creates a "minigame.sav" file.
After some saves you can see that it saves the player position, which Morty you have caught and the helpers & objects you got.
But, at the end of the file there is a 256bit alywas-changing signature.

We started reversing the challenge's binary file to understand how the signature was made, but then we stumbled upon the `winFunc` function.

Apparently the function is never called, so we decided to arbitrary call it.

GDB? Nah.
Frida? Nah.
We pathed the binary file.

Apparently every "level"/"stage" has its dedicated function that's called once you enter it, so the game can draw the "scene" and place the "sprites".

Last time we saved we were in level 7, so we decided to swap the call to `pausegame` (the function that is called when you press 'P') with a call to `winFunc` inside the `level7` function.

As simple as swapping `66492B00` for `5CBC0000` at offset `0x40AF76`.
PS: Those two are the relative offset for the [CALL opcode](https://www.felixcloutier.com/x86/call) in little endian form.

Then we started out patched binary, we loaded the savefile and pressed 'P'.

![flag](https://raw.githubusercontent.com/jbzteam/CTF/master/m0lecon2020/pnaIZd6.png)
