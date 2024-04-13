# PolytoriaMultiClients

Ever wanted to test your game on multiple clients? Well now you can!

> [!NOTE] 
> This will NEVER work on anything else than Windows. There are probably similiar ways to achieve this in other operating systems but I honestly cant be bothered. (Sorry Index)

Its not SUPER straight forward, but I tried my best at making it easy to use:

1. Either download a ready-to-use release
2. If you downloaded the release, unzip it (should be obvious)
3. Run "PolytoriaDontTerminate.exe" as an administrator.
4. Locate your polytoria client. Its usually under `%APPDATA%\Polytoria\Client\<Version>`. In that folder, open the `Polytoria Client_Data` folder and then open the `boot.config` file in your preferred editor. DELETE the line saying `single-instance=` and save the file.
5. You are ready to go! You only have to ensure that you use different accounts for each instance, as the Polytoria Servers properly kick out your old account if you join again (which can't be prevented)

## It doesnt work!
First of all, make sure you actually ran it as Administrator. Also make sure you have "DontTerminate.dll" in the same folder as your "PolytoriaDontTerminate.exe". NEVER rename the files. Then, if it still doesn't work, create an issue. **ATTACH THE FILE `%TEMP%/DontTerminate.log`** (if it doesnt exist, EXPLICITLY MENTION THAT)

## How does this work?
Well, its quite funky. It uses minhook to hook Win32-APIs to query, terminate and create processes to make the Polytoria client completely unaware that there is another one running. To actually hook the APIs, it injects a DLL into the Polytoria Launcher and Client.

## Will I get banned for this?
Whilst I can't gurantee that you wont get banned (since its DLL injection after all), I think its highly unlikely that you will get banned unless you abuse this to, e.g. bot your player count, or other malicious purposes.

## Help! My anti virus marks this as a virus!
Anti viruses dont like DLL injections, as they are commonly used by malware. This is an open source project, you can safely ignore your anti virus. If you don't trust my releases, you can compile it yourself using Visual Studio 2022.
