---
title: "Javascwipt Fwamework - Hackfest 2023"
date: 2023-11-03T15:30:28-04:00
author: "1t1n1"
cover: "/images/javascwipt_fwamework/javascwipt_fwamework_4.png"
description: "A Reverse Engineering challenge involving multiple layers of JavaScript Obusfaction, presented at Hackfest 2023"
showFullContent: false
readingTime: false
hideComments: false
color: ""
---
This challenge was a somewhat typical Javascript obfuscation challenge given at Hackfest 2023, which takes place in the vicinity of Quebec City once a year. I had never completed one before, so I was happy to tackle this one, hoping I could reach the final flag. 🚩

## Getting the Code

When I first opened the challenge on CTFd, I was greeted with the following:

> Oh no, we might have travelled too far in the future Marty, I don't know what sort of futuwistic code this is anymowe >_<.

I knew that the event's theme was "Back to the Future", but even with that info, the previous sentence didn't make much sense. So I proceeded with the next logical step: Open the file.

![Figure 1. File in VSCode](/images/javascwipt_fwamework/javascwipt_fwamework_1.png)

As logical as it sounded, opening the file yielded nothing. It looked like I was given a blank file. _Is that a joke?_ It could be, but chances were that I simply overlooked something. There could have been a problem with the download too, but my connection seemed strong. So I wondered, _what is the size of the file?_ A simple `ls -lh ledgitjs.js` was enough to answer my question.

> -rw-r--r-- 1 group user 2.6M Oct 13 20:03 ledgitjs.js


Ooof. 2.6 MB is quite the file for an empty script. There had to be something I was missing. So I decided to play with the file and realized that I could place my cursor anywhere on the VSCode window without problem. _Is the file filled with spaces?_ I tried to select everything with CTRL+A and here's what I got:

![Figure 2. Spaces and tabs appear](/images/javascwipt_fwamework/javascwipt_fwamework_2.png)

The file was filled with spaces and tabs. I first wondered if it was possible to obfuscate Javascript in such a way, but knowing the Hackfest I was able to guess right away what I was dealing with: binary. As a matter of fact, a simple Cyberchef manipulation changing spaces into 1s and tabs into 0s and converting binary to ascii provided me with a more standard, yet still obfuscated, Javascript file.

## JSFuck

![Figure 3. Code composed of 6 characters](/images/javascwipt_fwamework/javascwipt_fwamework_3.png)

Though not the most typical Javascript, the file I recovered only contained 6 characters: `()+[]!`. From experience, I knew right away that this was a sample of [JSFuck](https://jsfuck.com/) obfuscated Javascript. I was lucky because this information saved my a lot of time and research. Knowing this, I was able to look for a decoder online and [found one](https://enkhee-osiris.github.io/Decoder-JSFuck/).

This resulted in landing the following script:

```js
function hexToBytes(hex) {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
	}
	return bytes;
}
function decodeAndExecute(hexData) {
	const byteData = hexToBytes(hexData);
	const decompressed = pako.inflate(byteData, { to: 'string' });
	eval(decompressed);
}
const hexCompressedJS = '1f8b0800bed6fd6400ffed9d3b921b470f8...'; // Truncated the hex string because it was way too long
decodeAndExecute(hexCompressedJS);
```

A quick analysis shows that the program simply inflates the long hex string and executes it, which tells us that this is where we should be heading. Now this is a little more tricky because pako is a library so I couldn't just run the code in my browser's console and fetch the decoded's JavaScript. So my solution was to build a NodeJS project, import the library, use it and finally print the code in the console! Here's what I got:

![Figure 4. Decoded JSFuck](/images/javascwipt_fwamework/javascwipt_fwamework_4.png)

## Unusual Characters

This new code is not nearly as readable as the previous one, but I managed to get throught it. First, I used my browser's builtin "pretty print" tool to separate lines of code, which gave the following:

![Figure 5. Browser Console Pretty Printed](/images/javascwipt_fwamework/javascwipt_fwamework_5.png)

The first lines seemed like they were initializing variables. They were also followed by a super long line that went on until the end of the code so I assumed that it must be the actual code that I need to understand. However, to do so I had to improve the code's readability. So first thing I did was recognize that the variable that stands at the beginning of most line is a dictionary so I renamed it... dictionary!

Then I decided to execute the code, but removed the last line. This resulted in my console's environment having every variable set, but no important code executed yet. This way, I was able to retreive the value of each variable one by one and easily search and replace the unusual characters that composed them with the variable's value. This made the code a lot more readable. Here's a sample of the last line once every variable was converted:

```js
dictionary['_'](dictionary['_']("return"+dictionary["constructor"]+dictionary["return"]+4+0+dictionary["return"]+4+0+dictionary["return"]+4+0+dictionary["return"]+4+0+dictionary["return"]+4+0+dictionary["return"]+4+0+dictionary["return"]+4+0+dictionary["return"]+4+0+dictionary["return"]+1+4+3+dictionary["return"]+1+(4+1)+(4+3)+dictionary["return"]+1+(4+1)+(3+3)+dictionary["return"]+1+(3+3)+3+dictionary["return"]+1+(3+3)+4+dictionary["return"]+ ... /* Truncated */ 3+dictionary["constructor"]), 1) ('_'); // Once again, truncated because the line was way too long
```

Now you must know that `dictionary["return"]` was set to return the string `"\\"`. Also, since the very long addition first started with a string on the left side, the numbers that are added are concatenated to the resulting string ([more info about this](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Addition)). In the end, here's what I got when I evaluated the addition and placed the result in the previous code:

```js
dictionary['_'](dictionary['_']('return "\40\40\40\40\40\40\40\40\143\157\156\163\164\40\125\167\125\40\75\40\47\65\67\66\65\66\61\66\143\64\142\66\65\67\71\62\61\65\67\66\65\66\61\66\143\64\142\66\65\67\71\62\61\65\67\66\65\66\61\66\143\64\142\66\65\67\71\62\61\65\67\66\65\66\61\66\143\64\142\66\65\67\71\62\61\47\73\40\57\57\123\145\143\167\145\164\72\47\143\142\142\65\60\63\63\62\65\145\64\60\146\67\66\66\67\70\60\66\70\145\64\62\142\70\141\63\61\144\71\67\61\144\61\142\142\63\67\144\142\142\145\142\63\71\146\67\67\65\70\145\142\144\62\145\145...\51\73"'), 1) ('_'); // You're getting it now... Yeah, the line was too long
```

## Final Steps

Now you can easily see that there is a hidden encoded string here, so I decoded it and got the following:

```js
const UwU = '5765616c4b6579215765616c4b6579215765616c4b6579215765616c4b657921'; //Secwet:'cbb503325e40f76678068e42b8a31d971d1bb37dbbeb39f7758ebd2ee7cb0598';

function hexToUint8Array(hexString) {
	const OwO = new Uint8Array(hexString.length / 2);
	for (let i = 0; i < hexString.length; i += 2) {
		OwO[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
	}
	return OwO;
}

async function decwypt(encwyptedTextHex, UwU) {
	const iv = hexToUint8Array(encwyptedTextHex.substring(0, 32));
	const encwyptedData = hexToUint8Array(encwyptedTextHex.substring(32));

	const UwUBuffer = hexToUint8Array(UwU);
	const x3 = await crypto.subtle.importKey(
		'raw',
		UwUBuffer,
		{ name: 'AES-CBC', length: 256 },
		false,
		['decrypt']
	);

	try {
		const decwyptedData = await crypto.subtle.decrypt(
			{
				name: "AES-CBC",
				iv: iv
			},
			x3,
			encwyptedData
		);

		const decoder = new TextDecoder();
		return decoder.decode(decwyptedData);
	} catch (e) {
		return 'OwO what\\'s this decwyption did a woopsie';
	}
}

(async function() {
	const ciphertext = '3877e41b75f60fe872402f6b334312f9617ca298ed5e9939a8d2e812456696b83b5435213f6715dfedbd11f92bcf2eada760e4cd9043062a189c93a655fd0e82';
	const decwyptedText = await decwypt(ciphertext, UwU);
	console.log('Fwag >_<:', decwyptedText);
})();
```

As you can see from a quick look at the code, it decrypts a ciphertext to print the flag (_or should I say the Fwag_). I didn't want to struggle with writing my own python crypto code or even spend some time making CyberChef work so I tried to simply run the script... which didn't work. I did change the secret's value (`UwU`), but my error was unrelated: `Uncaught SyntaxError: unexpected token: identifier`. What is that? Do I really want to spend some time debugging this code? I decided that I could give it a few tries before using another tool. First thing I saw, was that the last returned string wasn't closed properly, so I tried to fix it:

```js
return 'OwO what\\'s this decwyption did a woopsie';
```
```js
return 'OwO what\'s this decwyption did a woopsie';
```

Now when I ran the code, I got the flag!

> Fwag >_<: HF-02574f96342c32ce1f641039dceab768

## Closing Thoughts

In the end, this was a very fun challenge that let me learn about different JavaScript obfuscation techniques. Also, having so many layers made it a lot more rewarding once I got the flag at the end!

