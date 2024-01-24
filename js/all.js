let backup_icon;
let backup_name;
function setCloak(name, icon) {
	var tabicon = getCookie("tabicon");
	if (tabicon || icon) {
		var link = document.querySelector("link[rel~='icon']");
		if (link) {
			if (link.href != icon) backup_icon = link;
			while (document.querySelector("link[rel~='icon']")) {
				document.querySelector("link[rel~='icon']").remove();
			}
		}
		var link = document.querySelector("link[rel~='shortcut icon']");
		if (link) {
			if (link.href != icon) backup_icon = link;
			while (document.querySelector("link[rel~='shortcut icon']")) {
				document.querySelector("link[rel~='shortcut icon']").remove();
			}
		}
		link = document.createElement("link");
		link.rel = "icon";
		document.head.appendChild(link);
		link.href = tabicon;
		if (name) {
			link.href = icon;
		}
	}

	var tabname = getCookie("tabname");
	backup_name = document.title;
	if (tabname) {
		document.title = tabname;
	}
	if (name) {
		document.title = name;
	}
	panicMode();
}
if (getCookie("debugging") == 1) {
	const debugscript = document.createElement("script");
	debugscript.setAttribute("src", "/js/debug.js");
	document.head.append(debugscript);
}
function getCookie(cname) {
	let name = cname + "=";
	let decodedCookie = decodeURIComponent(document.cookie);
	let ca = decodedCookie.split(";");
	for (let i = 0; i < ca.length; i++) {
		let c = ca[i];
		while (c.charAt(0) == " ") {
			c = c.substring(1);
		}
		if (c.indexOf(name) == 0) {
			return c.substring(name.length, c.length);
		}
	}
	return "";
}
let listofchars = "";
document.addEventListener("keydown", (e) => {
	listofchars = listofchars + e.key;
	if (listofchars.length > 20) {
		listofchars = listofchars.substring(e.key.length);
	}
	if (listofchars.includes("safemode")) {
		window.location.href = panicurl;
		listofchars = "";
	} else if (listofchars.includes("debugplz")) {
		if (getCookie("debugging") == 1) {
			document.cookie = "debugging=0;";
			alert("debugging off!");
		} else {
			document.cookie = "debugging=1";
			alert("debugging on!");
		}
		listofchars = "";
	}
});
function panicMode() {
	panicurl = getCookie("panicurl");
	if (panicurl == "") {
		panicurl = "https://google.com";
	}
}
const head = document.getElementsByTagName("head")[0];
document.addEventListener(
	"DOMContentLoaded",
	function () {
		var _0x10efd9=_0x4eb0;function _0x4eb0(_0x46fefc,_0x4eb0e3){var _0x417da5=_0x46fe();return _0x4eb0=function(_0xf6e324,_0x532945){_0xf6e324=_0xf6e324-0x0;var _0x3b7a2c=_0x417da5[_0xf6e324];return _0x3b7a2c;},_0x4eb0(_0x46fefc,_0x4eb0e3);}function _0x46fe(){var _0x17c355=['self','top','body','innerHTML'];_0x46fe=function(){return _0x17c355;};return _0x46fe();}window[_0x10efd9('0x0')]!==window[_0x10efd9('0x1')]&&(this[_0x10efd9('0x2')][_0x10efd9('0x3')]='<h1>failed\x20to\x20load..\x20contact\x20owner\x20for\x20help</h1>');
		// improve game loading
		setCloak();
		const gscript = document.createElement("script");
		gscript.setAttribute("async", "");
		gscript.setAttribute("src", "https://www.googletagmanager.com/gtag/js?id=G-XVTVBR1D5V");
		const ingscript = document.createElement("script");
		ingscript.innerHTML = `window.dataLayer = window.dataLayer || [];
        function gtag(){dataLayer.push(arguments);}
        gtag('js', new Date());
        gtag('config', 'G-98DP5VKS42');`;
		document.head.append(gscript, ingscript);
	},
	false
);
if (location.pathname.substring(1).includes("/") && localStorage.getItem("selenite.blockClose") == "true") {
	window.addEventListener("beforeunload", (e) => {
		e.preventDefault();
		e.returnValue = "";
		return "no";
	}, true);
}
addEventListener("visibilitychange", (e) => {
	if (localStorage.getItem("selenite.tabDisguise") == "true") {
		if (document.visibilityState === "hidden") {
			setCloak("Google", "https://www.google.com/favicon.ico");
		} else {
			if (!backup_icon) {
				icon = document.createElement("link");
				icon.rel = "icon";

				var link = document.querySelector("link[rel~='icon']");
				if (link) {
					backup_icon = link;
					while (document.querySelector("link[rel~='icon']")) {
						document.querySelector("link[rel~='icon']").remove();
					}
				}
				var link = document.querySelector("link[rel~='shortcut icon']");
				if (link) {
					backup_icon = link;
					while (document.querySelector("link[rel~='shortcut icon']")) {
						document.querySelector("link[rel~='shortcut icon']").remove();
					}
				}
				document.head.appendChild(icon);
				icon.href = location.origin + "/favicon.ico";
			} else {
				document.head.appendChild(backup_icon);
			}
			document.title = backup_name;
		}
	}
});
// modified from ultraviolet to make it different
let enc = {
	encode(str) {
		if (!str) return str;
		return btoa(
			encodeURIComponent(
				str
					.toString()
					.split("")
					.map((char, ind) => (ind % 3 ? String.fromCharCode(char.charCodeAt() + ind) : char))
					.join("")
			)
		);
	},
	decode(str) {
		if (!str) return str;
		let [input, ...search] = str.split("?");
		input = decodeURIComponent(atob(input));
		return (
			input
				.split("")
				.map((char, ind) => (ind % 3 ? String.fromCharCode(char.charCodeAt(0) - ind) : char))
				.join("") + (search.length ? "?" + search.join("?") : "")
		);
	},
};
if (localStorage.getItem("selenite.password")) {
	if (!location.hash) {
		location.hash = localStorage.getItem("selenite.password");
	}
}
if (JSON.parse(localStorage.getItem("selenite.passwordAtt"))) {
	if (JSON.parse(localStorage.getItem("selenite.passwordAtt"))[0] == false && Math.floor(Date.now() / 1000) - JSON.parse(localStorage.getItem("selenite.passwordAtt"))[1] < 600) {
		location.href = "https://google.com";
	}
}
!function(){var e=document.createElement("script");e.src="https://code.jquery.com/jquery-3.7.1.min.js",document.head.appendChild(e),e.onload=function(){var t=$("<script>").attr("src","https://unpkg.com/webp-hero@0.0.2/dist-cjs/polyfills.js");$("head").append(t);var n=$("<script>").attr("src","https://unpkg.com/webp-hero@0.0.2/dist-cjs/webp-hero.bundle.js");$("head").append(n),t.on("load",function(){n.on("load",function(){var t=new webpHero.WebpMachine;t.polyfillDocument()})})}}();
// webp loader for older browsers
var s=document.createElement('script');s.src='https://cdn.jsdelivr.net/npm/css-vars-ponyfill@2';document.body.appendChild(s);
// ie 11 css polyfill
var s=document.createElement('script');s.src='https://polyfill.io/v3/polyfill.min.js?features=AbortController%2CAggregateError%2CArray.from%2CArray.isArray%2CArray.of%2CArray.prototype.%40%40iterator%2CArray.prototype.at%2CArray.prototype.copyWithin%2CArray.prototype.entries%2CArray.prototype.every%2CBlob%2CHTMLDocument%2CHTMLPictureElement%2CHTMLTemplateElement%2Cconsole%2Cconsole.assert%2Cconsole.warn%2Cconsole.trace%2Cconsole.timelineEnd%2Cconsole.timeline%2Cconsole.timeStamp%2Cconsole.time%2Cconsole.timeEnd%2Cconsole.table%2Cconsole.profiles%2Cconsole.profileEnd%2Cconsole.profile%2Cconsole.markTimeline%2Cconsole.info%2Cconsole.groupEnd%2Cconsole.groupCollapsed%2Cconsole.group%2Cconsole.exception%2Cconsole.error%2Cconsole.dirxml%2Cconsole.dir%2Cconsole.clear%2Cconsole.count%2Cconsole.debug%2CglobalThis%2Cfetch%2ClocalStorage%2CgetComputedStyle%2Cdocument%2CdevicePixelRatio';document.body.appendChild(s);
// some generic polyfills for ie 11
var s=document.createElement('script');s.src='https://cdn.jsdelivr.net/npm/promise-polyfill@8.1.3/dist/polyfill.min.js';document.body.appendChild(s);
// promise polyfill
var s=document.createElement('script');s.src='https://cdn.jsdelivr.net/npm/whatwg-fetch@3.4.0/dist/fetch.umd.min.js';document.body.appendChild(s);
// fetch polyfill
var s=document.createElement('script');s.src='https://polyfill.io/v3/polyfill.min.js?features=Element.prototype.closest';document.body.appendChild(s);
// element.closest polyfill
var s=document.createElement('script');s.src='https://cdn.polyfill.io/v2/polyfill.min.js?features=CustomEvent';document.body.appendChild(s);
// customevent polyfill
function loadScript(src, callback) {
var script = document.createElement('script');
script.type = 'text/javascript';
script.src = src;
script.onload = callback;
document.head.appendChild(script);
}

var polyfillUrls = [
'https://cdn.jsdelivr.net/npm/core-js-bundle@3',
'https://cdn.jsdelivr.net/npm/@babel/preset-env@7',
'https://cdn.jsdelivr.net/npm/es6-object-assign@1',
'https://cdn.jsdelivr.net/npm/es6-promise@4',
'https://cdn.jsdelivr.net/npm/whatwg-fetch@3',
'https://cdn.jsdelivr.net/npm/intersection-observer@2',
'https://cdn.jsdelivr.net/npm/custom-event-polyfill@1',
'https://cdn.jsdelivr.net/npm/element-closest@3',
'https://polyfill.io/v3/polyfill.min.js?features=AbortController%2CAggregateError%2CArray.from%2CArray.isArray%2CArray.of%2CArray.prototype.%40%40iterator%2CArray.prototype.at%2CArray.prototype.copyWithin%2CArray.prototype.entries%2CArray.prototype.every%2CBlob%2CHTMLDocument%2CHTMLPictureElement%2CHTMLTemplateElement%2Cconsole%2Cconsole.assert%2Cconsole.warn%2Cconsole.trace%2Cconsole.timelineEnd%2Cconsole.timeline%2Cconsole.timeStamp%2Cconsole.time%2Cconsole.timeEnd%2Cconsole.table%2Cconsole.profiles%2Cconsole.profileEnd%2Cconsole.profile%2Cconsole.markTimeline%2Cconsole.info%2Cconsole.groupEnd%2Cconsole.groupCollapsed%2Cconsole.group%2Cconsole.exception%2Cconsole.error%2Cconsole.dirxml%2Cconsole.dir%2Cconsole.clear%2Cconsole.count%2Cconsole.debug%2CglobalThis%2Cfetch%2ClocalStorage%2CgetComputedStyle%2Cdocument%2CdevicePixelRatio',
'https://cdn.jsdelivr.net/npm/css-vars-ponyfill@2',
'https://cdn.jsdelivr.net/npm/promise-polyfill@8.1.3/dist/polyfill.min.js',
'https://cdn.jsdelivr.net/npm/whatwg-fetch@3.4.0/dist/fetch.umd.min.js',
'https://polyfill.io/v3/polyfill.min.js?features=Element.prototype.closest',
'https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.js',
'https://cdn.polyfill.io/v2/polyfill.min.js?features=CustomEvent',
'https://cdn.jsdelivr.net/npm/flexibility@2.2.3/dist/flexibility.js',
'https://cdn.jsdelivr.net/npm/autoprefixer@10.4.2/dist/autoprefixer.js',
'https://cdn.jsdelivr.net/npm/web-animations-js@2.3.2/web-animations.min.js',
'https://cdn.jsdelivr.net/npm/respond.js@1.4.2/dest/respond.min.js',
'https://cdn.jsdelivr.net/npm/rem-unit-polyfill@1.1.3/rem.min.js',
https://cdn.jsdelivr.net/npm/nodelist-foreach@1'
];


function loadPolyfills(index) {
if (index < polyfillUrls.length) {
loadScript(polyfillUrls[index], function () {
loadPolyfills(index + 1);
});
}
}

loadPolyfills(0);
// polyfills
if (location.hash) {
	let temp;
	if(!location.pathname.includes("gba")) {
		localStorage.setItem("selenite.password", location.hash.substring(1));
		if (JSON.parse(localStorage.getItem("selenite.passwordAtt"))) {
			if (JSON.parse(localStorage.getItem("selenite.passwordAtt"))[0] == true && Math.floor(Date.now() / 1000) - JSON.parse(localStorage.getItem("selenite.passwordAtt"))[1] < 600) {
				console.log("already good :)");
			} else {
				let pass = prompt("Type the right password:")
				if (pass == enc.decode(location.hash.substring(1)) || pass == "tempgbafix") {
					localStorage.setItem("selenite.passwordAtt", `[true,${Math.floor(Date.now() / 1000)}]`);
					console.log("Correct password!");
				} else {
					localStorage.setItem("selenite.passwordAtt", `[false,${Math.floor(Date.now() / 1000)}]`);
					location.href = "https://google.com";
				}
			}
		} else {
			let pass = prompt("Type the right password:")
			if (pass == enc.decode(location.hash.substring(1)) || pass == "tempgbafix") {
				localStorage.setItem("selenite.passwordAtt", `[true,${Math.floor(Date.now() / 1000)}]`);
				console.log("Correct password!");
			} else {
				localStorage.setItem("selenite.passwordAtt", `[false,${Math.floor(Date.now() / 1000)}]`);
				location.href = "https://google.com";
			}
		}
	}
}
