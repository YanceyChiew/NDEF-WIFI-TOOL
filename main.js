(() => {
	
	const VERSION = Uint8Array.from([0x10, 0x4A])
	const CREDENTIAL = Uint8Array.from([0x10, 0x0e])
	const AUTH_TYPE = Uint8Array.from([0x10, 0x03])
	const CRYPT_TYPE = Uint8Array.from([0x10, 0x0F])
	const MAC_ADDRESS = Uint8Array.from([0x10, 0x20])
	const NETWORK_IDX = Uint8Array.from([0x10, 0x26])
	const NETWORK_KEY = Uint8Array.from([0x10, 0x27])
	const NETWORK_NAME = Uint8Array.from([0x10, 0x45])
	const OOB_PASSWORD = Uint8Array.from([0x10, 0x2C])
	const VENDOR_EXT = Uint8Array.from([0x10, 0x49])
	const VENDOR_WFA = Uint8Array.from([0x00, 0x37, 0x2A])
	const VERSION2 = Uint8Array.from([0x00])
	const KEY_SHAREABLE = Uint8Array.from([0x02])
	const AUTH_OPEN = Uint8Array.from([0x00, 0x01])
	const AUTH_WPA_PERSONAL = Uint8Array.from([0x00, 0x02])
	const AUTH_SHARED = Uint8Array.from([0x00, 0x04])
	const AUTH_WPA_ENTERPRISE = Uint8Array.from([0x00, 0x08])
	const AUTH_WPA2_ENTERPRISE = Uint8Array.from([0x00, 0x10])
	const AUTH_WPA2_PERSONAL = Uint8Array.from([0x00, 0x20])
	const AUTH_WPA_WPA2_PERSONAL = Uint8Array.from([0x00, 0x22])
	const CRYPT_NONE = Uint8Array.from([0x00, 0x01])
	const CRYPT_WEP = Uint8Array.from([0x00, 0x02])
	const CRYPT_TKIP = Uint8Array.from([0x00, 0x04])
	const CRYPT_AES = Uint8Array.from([0x00, 0x08])
	const CRYPT_AES_TKIP = Uint8Array.from([0x00, 0x08])
	const MAC_ANY_ADDRESS = Uint8Array.from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
	
	const utf8Encode = new TextEncoder('utf-8')
	
	class NdefWifiRecord {
		
		static authTypes = {
			auth_open: AUTH_OPEN,
			auth_shared: AUTH_SHARED,
			auth_wpa_personal: AUTH_WPA_PERSONAL,
			auth_wpa2_personal: AUTH_WPA2_PERSONAL,
			auth_wpa_wpa2_personal: AUTH_WPA_WPA2_PERSONAL,
			auth_wpa_enterprise: AUTH_WPA_ENTERPRISE,
			auth_wpa2_enterprise: AUTH_WPA2_ENTERPRISE
		}
		
		static cryptTypes = {
			crypt_none: CRYPT_NONE,
			crypt_wep: CRYPT_WEP,
			crypt_skip: CRYPT_TKIP,
			crypt_aes: CRYPT_AES,
			crypt_aes_skip: CRYPT_AES_TKIP
		}
		
		constructor(options) {
			// This field seems useless, when there are multiple idx, the phone only shows the last one
			this.idxBytes = Uint8Array.from([options.idx])
			this.authBytes = this.constructor.authTypes[options.authType]
			this.cryptBytes = this.constructor.cryptTypes[options.cryptType]
			this.ssidBytes = utf8Encode.encode(options.ssid)
			this.passwordBytes = utf8Encode.encode(options.passwd)
			this.macAddrBytes = Uint8Array.from(options.macAddrArray)
			
			return new NDEFRecord( {
				recordType: "mime",
				mediaType: "application/vnd.wfa.wsc",
				data: this.assemblePayload()
			} )
		}
		
		assemblePayload() {
			function assmebleByteField(keyBytes, valueBytes) {
				// Expanding the array is less efficient, but more readable
				// Only a small amount of data is processed here
				return Uint8Array.from([...keyBytes, valueBytes.byteLength >> 8, valueBytes.byteLength % 256, ...valueBytes])
			}
			
			let idxField = assmebleByteField(NETWORK_IDX, this.idxBytes)
			let ssidField = assmebleByteField(NETWORK_NAME, this.ssidBytes)
			let authField = assmebleByteField(AUTH_TYPE, this.authBytes)
			let cryptField = assmebleByteField(CRYPT_TYPE, this.cryptBytes)
			let passwordField = assmebleByteField(NETWORK_KEY, this.passwordBytes)
			let macAddrField = assmebleByteField(MAC_ADDRESS, this.macAddrBytes)
			let payload = Uint8Array.from([...idxField, ...ssidField, ...authField, ...cryptField, ...passwordField, ...macAddrField])
			
			return assmebleByteField(CREDENTIAL, payload)
		}
	}

	eleLog = document.getElementById("p_log")
	function writelog(tag, msg) {
		eleLog.innerHTML = `> ${tag}: ${msg}`
	}
	
	inputElements = []
	
	eleAuthType = document.getElementById("s_authType")
	inputElements.push(eleAuthType)
	Object.keys(NdefWifiRecord.authTypes).forEach((k)=>{eleAuthType.options.add(new Option(k))})

	eleCryptType = document.getElementById("s_cryptType")
	Object.keys(NdefWifiRecord.cryptTypes).forEach((k)=>{eleCryptType.options.add(new Option(k))})
	inputElements.push(eleCryptType)

	elessid = document.getElementById("i_ssid")
	inputElements.push(elessid)
	elepasswd = document.getElementById("i_passwd")
	inputElements.push(elepasswd)
	elepasswdv = document.getElementById("b_passwd_v")
	inputElements.push(elepasswdv)
	elepasswdv.addEventListener("mouseenter", ()=>{
			elepasswdv.textContent = "+_+"
			elepasswd.type = "text"
		})
	elepasswdv.addEventListener("mouseleave", ()=>{
			elepasswdv.textContent = "-_-"
			elepasswd.type = "password"
		})

	elemacaddr = document.getElementById("i_macaddr")
	inputElements.push(elemacaddr)
	eleOJBK = document.getElementById("b_ok")
	inputElements.push(eleOJBK)
	
	if ('NDEFReader' in window) {
		const ndef = new NDEFReader()
		function writeWifiRecord(wifiRecord) {
			let message = {records: [wifiRecord]} // message = new NDEFMessage([wifiRecord]) -- NDEFMessage has constructor issue
			ndef.write(message).then(
				()=> {writelog("success", "write ✍️ o g8 k 👌")},
				()=> {writelog("fail", "write ✍️ o g8 not k 💩")}
			).finally(()=>{console.log("done.")})
		}
		eleOJBK.addEventListener("click", ()=>{
			let mc = elemacaddr.value.split(":").map((x)=>{return parseInt(x,16)})
			if (mc.length != 6 || mc.some((x)=>{return !(x>=0 || x <= 255) })) {
				writelog("error", "wrong mac address!")
				return
			}
			options = {
				idx: 1,
				authType: eleAuthType.options[eleAuthType.selectedIndex].value,
				cryptType: eleCryptType.options[eleCryptType.selectedIndex].value,
				ssid: elessid.value,
				passwd: elepasswd.value,
				macAddrArray: mc
			}
			wifiRecord = new NdefWifiRecord(options)
			console.log(wifiRecord)
			writelog("notice", "waiting for write...")
			writeWifiRecord(wifiRecord)
		})
	} else {
			inputElements.forEach((el)=>{el.disabled=true})
			writelog("warning", `<small>The current browser does not support Web NFC API, follow <a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_NFC_API#browser_compatibility">this</a> link to view supported browsers.</small>`)
	}

})()