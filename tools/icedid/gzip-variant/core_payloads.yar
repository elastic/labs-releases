rule core_payloads {
    strings:
		$browser_hook_payloads_decryption = {
			48 8D 35 [4]
			BF [4]
			EB ??
			48 8D 35 [4]
			BF [4]
			33 DB
			48 89 75 ??
			48 21 5D ??
			48 83 EF ??
			48 89 5D ??
			48 8D 04 37
			48 85 C0
			74 ??
			0F 10 00
			0F 11 45 ??
		}
    
    condition:
        all of them
}