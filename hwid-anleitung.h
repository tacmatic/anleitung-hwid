All methods of retrieving unique identifiers(HWIDs) on your PC
changelog:
Code:
6/11/2019: added video guids(registry keys).
6/10/2019: added another gotcha for disk serials. Also added another registry key that can be used to track you.
5/25/2019: added another way to retrieve disk serials.
5/21/2019: added more info about instance IDs.
5/17/2019: added info about retrieving serials from nvme devices.
5/16/2019: added some more info: refactored (3), added to etc 2 methods to possibly retrieve hwids. Added a new discovery about disk serials that are cached by MSFT.
5/13/2019: added info about WWN serials.
5/13/2019: added more info about smart serials.
We all know anti-cheats employ HWID tracking to monitor cheaters/developers, and prevent them from continuing to cheat in the video games they protect.

Some anti-cheats hash the serials before sending them to their server, but others will simply send it in plain text. This can make one feel that their privacy is violated.

Brief overview of what is covered:
1)Disk serials.
2)NIC mac address.
3)smbios.
4)Nvidia Gpu UUID.
5)MACs of neighboring devices(such as your router).
6)Registry keys
7)filesystem UUIDs(such as volume guids and diskids)
8)EFI uuids.
9)Monitor serials
10)Cached USB Serials.
11)Etc.
12)File times
13)Files with HWIDs
14)System Shadow Copies.
15)UPnP / SSDP USNs.
16)boot GUID/bcdedit UUIDs.
17)USN Journal IDs

1. Disk Serials:


by opening a handle to PhysicalDriveX (where X indicates an interger value usually from 0-9) you can send the following IOCTLs to retrieve disk serials:
Code:
IOCTL_STORAGE_QUERY_PROPERTY
SMART_RCV_DRIVE_DATA
these ioctls are both dispatched to disk.sys

IOCTL_STORAGE_QUERY_PROPERTY takes an input of _STORAGE_PROPERTY_QUERY and outputs a STORAGE_DEVICE_DESCRIPTOR into the SystemBuffer.

SMART_RCV_DRIVE_DATA takes an input of SENDCMDINPARAMS and returns SENDCMDOUTPARAMS.

An example of how you can spoof both of these can be seen in hdd serial spoofer without hooking and hdd serial spoofer


Another way to retrieve disk serials is by opening a handle to scsiX: (where x is the SSD #)
note: this only works for SSDs

you can send a IOCTL_SCSI_MINIPORT which takes and outputs a SRB_IO_CONTROL (note that at the end of the SRB_IO_CONTROL buffer is a SENDCMDINPARAMS/SENDCMDOUTPARAMS) with control code "IOCTL_SCSI_MINIPORT_IDENTIFY"
It will output a SRB_IO_CONTROL with a SENDCMDOUTPARAMS attached to the end, which you can spoof like this:
Code:
if (buffer_length >= sizeof SRB_IO_CONTROL) {
			SENDCMDOUTPARAMS *pOut =
				(SENDCMDOUTPARAMS *)((PUCHAR)buffer + sizeof(SRB_IO_CONTROL));
			if (pOut->cBufferSize > 0) {
				char serialNumber[64];
				unsigned short* disk_data = (unsigned short*)(pOut->bBuffer);
				ConvertToString(disk_data, 10, 19, serialNumber);
				spoof_serial(serialNumber);
				str_2_diskdata(disk_data, 10, serialNumber);
			}
		
	}
If you're wondering what the ConvertToString/str_2_diskdata is for, it's because the serials are encoded and must be decoded, spoofed, and then reencoded (these functions were made based upon code found in https://www.winsim.com/diskid32/diskid32.cpp ).
If you don't want to spoof SMART serials, you can disable them: https://www.unknowncheats.me/forum/2441916-post67.html (great find by IChooseYou)

Another way to retrieve smart serials is through IOCTL_ATA_PASS_THROUGH.

Smart devices also implement World Wide Name (WWN was introduced in ATA/ATAPI-7 and is mandatory since ATA8-ACS Revision 3b) which you might want to spoof:
https://github.com/mirror/smartmonto...acmds.cpp#L898

nvme drives also support smart, but through a different ioctl(NVME_PASS_THROUGH_SRB_IO_CODE) -> https://github.com/mirror/smartmonto...in32.cpp#L3695
read more here: https://www.unknowncheats.me/forum/2467462-post30.html

Disk serials can also be retrieved through the fdo extension of the disk device list.
You can read more about this method here: https://www.unknowncheats.me/forum/2474324-post33.html
(credits to Alexcub89 for this method)

gotchas:
If you spoof using the method n0Lin posted, it will not work for removable drives.
Another thing to note with n0Lin's spoofer is that he only covers RaidPort0, but on my system, my NVMe drive is located in RaidPort1 and my 3 SSDs in RaidPort0.

If you use n0Lin's method as well as hooking the IRP_MJ_DEVICE_CONTROL (in order to cover removable drives), make sure you don't double spoof the serial. For example, with IOCTL_STORAGE_QUERY_PROPERTY, you can do this by checking if the drive is not removable by looking at the BusType
Code:
if (buffer->BusType != STORAGE_BUS_TYPE::BusTypeSata && buffer->BusType != STORAGE_BUS_TYPE::BusTypeNvme) // (BusTypeUsb=removable drive).
				spoof_serial(serial);
warning: disk serials are also stored in registry, make sure that they match the values you spoof them to (covered in 6. c).

warning: ensure you spoof SMART serials properly by checking smartmontools.
https://github.com/mirror/smartmonto...r/os_win32.cpp
You can use the following command:
Code:
smartctl -a /dev/sdX (where X is a letter from a-z representing the device)
e.g. smartctl -a /dev/sda
to check if you've spoofed them properly.

Another gotcha for smart serials is that the checksum will be changed when you spoof them:
Code:
Warning! Drive Identity Structure error: invalid SMART checksum.
Quote:
Originally Posted by Novela
n0Lin method is also not work for IDE disks
disk.sys also contain serials inside its device extenstion
Another issue is that the powershell command Get-PhysicalDisk and Get-Disk will return your non-spoofed serials. You can fix this by running the powershell command:
Code:
Reset-PhysicalDisk *
Yet another gotcha for disk serials is that if you spoof the entire serial, the first 6-8 of the serial may contain non-unique info such as vendor id, by spoofing that you're giving away that you're spoofing your disk serials.

warning: this can also apply to other types of serials.

2. NIC MAC address.
Your NIC has two types of MAC addresses, permanent and current.

The current mac address can be spoofed easily from usermode by changing the NetworkAddress for the subkeys in
Code:
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\XXXX
(where XXXX is 0000-9999 indicating the subkey representing the nic)
You can also retrieve the current mac address / adapter GUID with GetAdaptersInfo, GetAdaptersAddresses, or through NetBIOS(credits to H4x0rKAPPA for noticing that).


then disabling & enabling the device will use the new mac from the registry(i've noticed it reloads the driver).

The permanent mac address is a tad bit harder to spoof, i'll explain why in a moment.

For the permanent mac address, you can retrieve it by either opening a handle to the nic GUID(XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX) or by the device instance path (\??\PCI\...) as seen in https://github.com/adrianyy/EACRever....sys/mac.c#L58

You can simply have it return the current mac address instead of the permanent for an easy spoof.

Why is it harder to spoof? Because the IOCTLs are usually handled by a custom network driver other than ndis.sys. Also, if you have multiple NICs, like for example, Ethernet and Wifi, your ethernet network driver is usually not the same as the one used for wifi. So you would need to hook both drivers.

You can of course disable your wifi adapter in device manager, so you would only have to hook the ethernet driver.

Another gotcha I need to mention is that the adapter GUID can be used to identify you.

Permanent mac addresses are also stored in ndis.sys:
Quote:
Originally Posted by Novela View Post
0x0012001B handled by nsiproxy.sys
deviceiocontrol->nsiproxy.sys(NsiEnumerateObjectsAllParametersEx)->netio.sys->"something"

0x1010101 and 0x1010102 handled by ndis.sys at the end, however sometimes for some reason its can be processed by custom driver so doesent matter if its spoofed in ndis.sys(except if you change mac at ndis initialization)

Mac lie inside miniport attributes of ndis miniport struct
Note that ndis miniport is global var

Code:
struct ndis_miniport
{
	//windows only 7-10
	char					pad1[8];					//0
	ndis_miniport			*nextminiport;				//8
	char					pad2[16];					//16
	ndis_driver				*driverhandle;				//32 
	void					*miniportadapterctx;		//40
	UNICODE_STRING			*miniport_name;				//48 "adapter name"  
    ...
 
};
 
 
    ULONG64 MiniportAddress = 0;
	
	MiniportAddress = FindPattern(ndisbase, "40 8A F0 48 8B 05");//win 7-10 
 
    if (!MiniportAddress)
		return false;
 
 
	MiniportAddress += 3;
 
	unsigned int offset = *(unsigned int*)(MiniportAddress + 3);
 
	ndis_miniport* g_pMiniport = *(ndis_miniport**)(MiniportAddress + 7 + offset);
 
	if (!IsValidKernelPtr(g_pMiniport))
		return false;
Offset to miniport attributes struct and both current and permanent mac depends on windows version
Spoofing without hooking the driver:
Quote:
Originally Posted by Novela
your NIC mac is stored in filter_block->Miniport->IfBlock, by spoofing that you can change your permanent mac address without having to hook the driver.
note: some custom drivers may return their own permanent mac address.
Permanent mac address is also cached in other places, one example you cans see in my post here: https://www.unknowncheats.me/forum/2454933-post15.html


3. SMBIOS / SYS ID
Smbios contains motherboard serials, ram serials, etc.

GetSystemFirmwareTable and IoWMIQueryAllData MSSmBios_RawSMBiosTables_GUID can both be spoofed by
Kernelmode SMBIOS Hardware ID Spoofing


gotchas:
data is cached by wmi by it's usermode service so make sure to restart Winmgmt service(warning: sys id is cached in kernel mode, but not smbios which is read directly from physical memory).

SMBIOS is also cached in registry (6. b)

4. NVIDIA GPU UUID / Serial Number
Running nvidia-smi -L (which is located in C:\Program Files\NVIDIA Corporation\NVSMI) will return your gpu uuid.
Example:
Code:
C:\Users\Admin>nvidia-smi -L
GPU 0: Tesla P100-SXM2-16GB (UUID: GPU-4f91f58f-f3ea-d414-d4ce-faf587c5c4d4)
The UUID is returned directly from the driver(nvlddmkm.sys) through the IOCTL 0x8DE0008 in irp->UserBuffer at offset 0x1AC.
Example:
Code:
#define GPU_SERIAL_OFFSET 0x1AC
		if (memcmp(&buffer[GPU_SERIAL_OFFSET], "GPU-", 4) == 0) {
			spoof_serial_gpu((char*)(&buffer[GPU_SERIAL_OFFSET + 4]));
		}
		else {
			DbgPrint(xorstr_("Bad GPU Serial Offset\r\n"));
			for (ULONG i = 0; i < 0x1FF; i++)
				if (memcmp(&buffer[i], "GPU-", 4) == 0) {
					DbgPrint("gpu serial offset: %X\r\n", i);
					spoof_serial((char*)(&buffer[i + 4]));
				}
		}
As pointed out by Muqtada newer NVIDIA GPUs also have serial numbers. You can read his post for more information.

5. ARP/neighbor table (router, laptops on your network, etc):

A very horrifying way to track users is through the arp table which contains your router and other devices on your network.

You can either:
SendARP and specify the IP of the device which will return the MAC address of the device. This will call NtDeviceIoControlFile with IOCTL 0x12000F to nsiproxy.sys,
which will return the mac address of the target in irp->UserBuffer:
Code:
if (**(PULONG*)(buffer + 0x10) == 24) { //SendARP Spoof
			buffer += 0x128;
			for (int i = 0; i < 6; i++)
				buffer[i] ^= st[i % sizeof(ULONGLONG)];
		}
(only tested on Win10, 1803 or 1809)
I have not seen any anti-cheats using SendARP, because instead they use GetIpNetTable2.

GetIpNetTable2 will return the ip neighbor table on your pc, which contains the ip:mac mappings, this includes your router, and other devices on your network.
It will send IOCTL 0x0012001B to nsiproxy which will return the mappings somewhere in irp->UserBuffer.
An example of spoofing:
Quote:
Originally Posted by gwendolin View Post
I took some time to reverse this with the help of this blog post http://mnin.blogspot.com/2011/03/vol...an-module.html

This should be a more "proper" way to accomplish the same thing
Code:
#define NSI_GET_INTERFACE_INFO 1 // this needs to be spoofed too (probably covered by (2))
#define NSI_GET_IP_NET_TABLE 11
 
struct NSI_PARAMS
{
  __int64 field_0;
  __int64 field_8;
  __int64 field_10;
  int Type;
  int field_1C;
  int field_20;
  int field_24;
  char field_42;
  __int64 AddrTable;
  int AddrEntrySize;
  int field_34;
  __int64 NeighborTable;
  int NeighborTableEntrySize;
  int field_44;
  __int64 StateTable;
  int StateTableEntrySize;
  int field_54;
  __int64 OwnerTable;
  int OwnerTableEntrySize;
  int field_64;
  int Count;
  int field_6C;
};
 
auto nsi_params = (NSI_PARAMS*)buffer;
if (nsi_params->Type == NSI_GET_IP_NET_TABLE)
  for (ULONG i = 0; i < nsi_params->Count; i++)
     auto mac = (PUCHAR)(nsi_params->NeighborTable+ i * nsi_params->NeighborTableEntrySize)

Quote:
Originally Posted by Skyfail View Post
Another way to retrieve mac addresses is IOCTL_TCP_QUERY_INFORMATION_EX to \Device\Tcp
(6) Registry keys

there are many keys that can be used to track you.
I will break them up into different parts, as some of these serials may be related to other methods of retrieving them(for example, smbios and disk serials are also stored in registry).

(a) Monitor Serials
Monitor data is stored in EDID format
They are located under a subkey in:
Code:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\DISPLAY\
 
e.g. the key might look like:
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\DISPLAY\Default_Monitor\4&574af1d&0&80872100&00&22\Device Parameters
they will be located in the value "EDID" (REG_BINARY).

There is also:
Code:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration
which has subkeys with unique ids and those subkeys also contain a "Timestamp" (REG_QWORD) value.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Connectivity
also has the same subkeys, but it doesn't have the timestamp value.
(b) SMBIOS
A copy of your SMBIOS table can be found in
Code:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios\Data
under the "SMBiosData" (REG_BINARY) value.

(c) Disk serials
Disk serials are located under the key:
Code:
HKEY_LOCAL_MACHINE\HARDWARE\DEVICEMAP\Scsi\Scsi Port X\Scsi Bus X\Target Id 0\Logical Unit Id 0
in the SerialNumber value (REG_SZ).

gotchas:
my nvme drive also contains its serial in DeviceIdentifierPage (REG_BINARY, doesn't appear to contain serials for my SSDs).

(d) Motherboard UUIDs
Code:
HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig -> "LastConfig" value (REG_SZ)
HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig\XXX which is a subkey with the motherboard UUID
HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\Common\\ClientTelemetry -> MotherboardUUID 
HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Office\\Common\\ClientTelemetry -> MotherboardUUID
HKEY_USERS\\S-1-5-18\\Software\\Microsoft\\Office\\Common\\ClientTelemetry -> MotherboardUUID
(e) Nvidia uuids?
Code:
HKEY_LOCAL_MACHINE\\SOFTWARE\\NVIDIA Corporation\\Global:
ClientUUID (REG_SZ)
PersistenceIdentifier (REG_SZ)
HKEY_LOCAL_MACHINE\\SOFTWARE\\NVIDIA Corporation\\Global\\CoProcManager:
ChipsetMatchID (REG_SZ)
(f) Volume GUIDs
Code:
/*
	You can also see all the volume GUIDs for every volume the OS has ever seen under the registry key:
	HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices
	--
	I called DeviceIoControl(IOCTL_MOUNTDEV_QUERY_UNIQUE_ID) and got a string as the similar format to Device Interface Path, but it is just different of the prefix 4 characters, and then it saved in registry \HKLM\SYSTEM\MountedDevices.
	*/
	SHDeleteKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\MountedDevices"); //e.g.: \??\Volume{<REDACTED>}
	SHDeleteKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume");
	SHDeleteValue(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket", L"LastEnum");
	SHDeleteKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC\\Volume");
	SHDeleteKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2");
	SHDeleteKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Dfrg\\Statistics");
(g)
Code:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM\WMI > WindowsAIKHash (REG_BINARY)
Code:
HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\MultifunctionAdapter\0\DiskController\0\DiskPeripheral\X (where X is a integer from 0-9) -> Identifier (e.g. 3bf866e1-17faa9bf-A)
(h) OfflineUniqueIDRandomSeed
Code:
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TPM\\ODUID -> RandomSeed (REG_BINARY)
(i) etc
Code:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography -> MachineGuid (REG_SZ)
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001 -> HwProfileGuid (REG_SZ)
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate:
SusClientId
SusClientIdValidation
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation:
ComputerHardwareId
ComputerHardwareIds
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Migration:
"IE Installed Date" (REG_BINARY)
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient:
MachineId (REG_SZ) (id that you can see when viewing "view your pc name")
WinSqmFirstSessionStartTime (REG_QWORD)
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\WSD\\UpdateAgent\\QueryParameters:
deviceId (related to above)
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\WSD\\Setup360\\QueryParameters:
deviceId (related to above)
 
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion:
InstallTime (REG_QWORD)
InstallDate (REG_DWORD)
BuildLab/BuildLabEx (REG_SZ, non unique but logged by ACs)
DigitalProductId
DigitalProductId4
 
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0001:
NetworkInterfaceInstallTimestamp (REG_QWORD)
 
SHDeleteKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests"); //telemetry.ASM-WindowsDefault, etc contain windows hardware id in "ETagQueryParameters", "ETag" may also contain unique value?
 
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleEventlogManager "LastEventlogWrittenTime"
 
HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Activation Technologies\\AdminObject\\Store:
MachineId (REG_SZ, very important as logged by ACs)
 
HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\Activation", L"ProductActivationTime"
 
SHDeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"BackupProductKeyDefault"); //<REDACTED>
	SHDeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"actionlist");
	SHDeleteValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", L"ServiceSessionId");
 
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist:
used by anti-cheats, not sure how.
(j) Non-unique
Code:
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000 -> DriverDesc(REG_SZ) for gpu
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0001:
DriverDesc (REG_SZ) -> for network adapter name
 
SHDeleteKey(HKEY_CURRENT_USER, xorstr_(L"Software\\Hex-Rays\\IDA\\History"));
	SHDeleteKey(HKEY_CURRENT_USER, xorstr_(L"Software\\Hex-Rays\\IDA\\History64"));
 
clean up your ida history^

(k)
(added 6/10/2019)
More unique serials from registry
Code:
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Win32kWPP\Parameters ->  WppRecorder_TraceGuid
(Credits: Object9999)
 
HKEY_LOCAL_MACHINE\HARDWARE\UEFI\ESRT\<RANDOM_KEY_UUID> 
 
HKEY_LOCAL_MACHINE\HARDWARE\DEVICEMAP\VIDEO:
\Device\Video0
\Device\Video1
\Device\Video2
\Device\Video3
\Device\Video4
(contains value with unique id)
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video
the 2 subkeys which match the values stored in the keys above.
(7) filesystem UUIDs:
note: if you only have one drive, and you reformat it after every ban, then you probably won't need to worry about any of the following.

If you have multiple drives, which you don't format often, then you may notice that there are unique IDs which can be used to identify you.

a) Volume GUIDs:
You can list volume GUIDs by:
https://docs.microsoft.com/en-us/win...e-volume-names
(they are also stored in registry under 6. f)

They are sent to the device located at MOUNTMGR_DEVICE_NAME (as defined in mountmgr.h *cough* definitely not an anti-paste)::
IOCTL_MOUNTMGR_QUERY_POINTS/IOCTL_MOUNTDEV_QUERY_UNIQUE_ID both return a MOUNTDEV_UNIQUE_ID structure in the SystemBuffer.
You will need to spoof:
Code:
MOUNTDEV_UNIQUE_ID::UniqueId
if I remember correctly, the disk unique ID is retrieved by IOCTL_DISK_GET_PARTITION_INFO_EX/IOCTL_DISK_GET_DRIVE_LAYOUT_EX which is handled by PartmgrControl(also handled by FltMgr at a higher level)
Code:
for IOCTL_DISK_GET_PARTITION_INFO_EX you check if PARTITION_INFORMATION_EX::PartitionStyle == PARTITION_STYLE_GPT
and if so you spoof PARTITION_INFORMATION_EX::Gpt.PartitionId.
Code:
for IOCTL_DISK_GET_DRIVE_LAYOUT_EX you do pretty much the same as above, except for each partition.
this will spoof https://docs.microsoft.com/en-us/win...mands/uniqueid
Code:
DISKPART> list disk
 
  Disk ###  Status         Size     Free     Dyn  Gpt
  --------  -------------  -------  -------  ---  ---
  Disk 0    Online          465 GB      0 B        *
  Disk 1    Online          465 GB  1024 KB        *
  Disk 2    Online          953 GB      0 B        *
  Disk 3    Online         3725 GB      0 B        *
 
DISKPART> select disk 0
 
Disk 0 is now the selected disk.
 
DISKPART> uniqueid disk
 
Disk ID: {SERIAL}
 
DISKPART>
gotchas:
the spoofed disk unique id will not show until you send IOCTL_DISK_UPDATE_PROPERTIES to the drive.

You can spoof the disk unique id from usermode by IOCTL_DISK_SET_PARTITION_INFO_EX, but you must not ever do it for a drive that has an OS or master boot record.

volume serial number:
Code:
vol c:
 Volume in drive C is LABEL
 Volume Serial Number is XXXX-XXXX
It can be retrieved with GetVolumeInformation, I cannot remember the exact ioctl(it started with FSCTL_XXX) but you can spoof it easily from usermode by doing:
Code:
bool spoof_volume_id(char drive)
{
	const int max_pbsi = 3;
 
	struct partial_boot_sector_info
	{
		LPCSTR Fs; // file system name
		DWORD FsOffs; // offset of file system name in the boot sector
		DWORD SerialOffs; // offset of the serialnumber in the boot sector
	};
 
	partial_boot_sector_info pbsi[max_pbsi] =
	{
	 {"FAT32", 0x52, 0x43},
	 {"FAT",   0x36, 0x27},
	 {"NTFS",  0x03, 0x48}
	};
 
	char buf[64];
	sprintf_s(buf, "\\\\.\\%c:", drive);
 
	HANDLE hFile = CreateFileA(buf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	BYTE sector[0x200];
	DWORD dwBytesRead;
	bool result = false;
	if (ReadFile(hFile, sector, sizeof(sector), &dwBytesRead, nullptr)) {
		int i;
		for (i = 0; i < max_pbsi; i++)
		{
			if (strncmp(pbsi[i].Fs, (const char*)(sector + pbsi[i].FsOffs), strlen(pbsi[i].Fs)) == 0)
			{
				// we found a valid signature
				break;
			}
		}
 
		if (i < max_pbsi) {
			printf("drive: %c, Serial: %X\r\n", drive, *(PDWORD)(sector + pbsi[i].SerialOffs));
			*(PDWORD)(sector + pbsi[i].SerialOffs) ^= generate_volume_serial_number();
			printf("drive: %c, Spoofed Serial: %X\r\n", drive, *(PDWORD)(sector + pbsi[i].SerialOffs));
			if (INVALID_SET_FILE_POINTER != SetFilePointer(hFile, NULL, NULL, FILE_BEGIN)) {
				DWORD dwBytesWritten;
				result = ::WriteFile(hFile, sector, sizeof(sector), &dwBytesWritten, nullptr) == TRUE;
			}
		}
		else
			printf("unknown fs\r\n");
	}
 
	::CloseHandle(hFile);
	return result;
}
note: based upon some of the code from: https://github.com/lallousx86/Volume...eSerialDlg.cpp


(8)EFI UUIDs:
I had not known about this until recently but:
hdd serial spoofer without hooking
You can call ZwQuerySystemEnvironmentValueEx to log the OfflineUniqueIDRandomSeed variable.
gotchas:
there's a registry key(6. h) which contains the OfflineUniqueIDRandomSeed.

The way this variable is retrieved may differ on your system:
Code:
2-3 different devices it can send an ioctl to, ioctl codes:
0x568004 ioctl w/ IRP_MJ_DEVICE_CONTROL
 
0x520004 ioctl w/ IRP_MJ_INTERNAL_DEVICE_CONTROL
 
or it can call HalGetEnvironmentVariableEx which is what my system uses

(9) Monitor serials
You can either read the serials with I2C or through the registry key in 6. a.

(10) Cached USB Serials.
I also believe this deserves a section separate from registry keys because it's very interesting. I was using the USBDeview tool when I noticed that some of my devices had a serial.

RGB Mouse pads, flash drives, headphones, these all can have unique serials.


Even when you remove a flash drive, its serial will be cached in the registry for use with the SetupAPIs(e.g. through SetupDiGetClassDevs GUID_DEVINTERFACE_DISK and any usb device with the flag CM_DEVCAP_UNIQUEID).

I am not sure how you can query their serial normally, but they are cached in the registry.

I've also had trouble with spoofing the serials when the device is still plugged in but didn't look deeply into it as you can simply remove the device & clean the registry.

Quote:
Originally Posted by kokole
Also device info (SetupDiGetDeviceRegistryPropertyW, SetupDiGetDeviceInstanceIdW, SetupDiGetDevicePropertyW). Used by Fortnite for HWID, I think it was for the instance IDs.
They may also be using the instance IDs as a hwid. -> https://docs.microsoft.com/en-us/win...l/instance-ids

(12) Filetimes
Some anti-cheats take filetimes of multiple system files and of game files. I believe they use the last written time or creation time to uniquely identify you.
You can simply use SetFileTime to spoof the filetime.
gotchas:
system files are owned by TrustedInstaller and cannot be opened for writing their filetimes, you must take temporary ownership(make sure to restore the original ownership!) and set write privileges for your account, spoof the filetime, then restore.

(13) Files with serials.
C:\Windows\System32\restore\MachineGuid.txt contains a uuid which is used by anti-cheats (credits to agent_dark64 for finding this, https://www.unknowncheats.me/forum/2331523-post15.html ).
some other files/folders which contain serials:
X:\$Recycle.Bin - may contain folders with account SIDs.

Code:
%windir%\INF\setupapi.dev.log - may contain usb serials.
%windir%\INF\setupapi.setup.log - also may contain usb serials.
An anti-cheat would have to parse the log files to find your serials, but it can be done.

(14)System Shadow Copies
I've noticed system shadow copies can contain unique IDs, to delete them, you can simply run the command:
Code:
vssadmin delete shadows /All
warning: I don't think any AC uses them & be aware that you are deleting your system restore points.

(15) Using Universal Plug and Play (UPnP) / SSDP to retrieve serials.
If you have UPnP enabled in your router, it may expose a serial number & unique identifier:

Simply disable UPnP in your router to prevent this.
Other devices that support UPnP may also need to be checked.


Yet another way is to use SSDP:
according to https://tools.ietf.org/html/draft-cai-ssdp-v1-03
Code:
  The following provides an overview of the data provided in a SSDP
   system.
 
   Services are identified by a unique pairing of a service type URI
   and a Unique Service Name (USN) URI.
 
   Service types identify a type of service, such as a refrigerator,
   clock/radio, what have you. The exact meaning of a service type is
   outside the scope of this specification. For the purposes of this
   specification, a service type is an opaque identifier that
   identifies a particular type of service.
 
   A USN is a URI that uniquely identifies a particular instance of a
   service. USNs are used to differentiate between two services with
   the same service type.
 
   In addition to providing both a service type and a USN, discovery
   results and presence announcements also provide expiration and
   location information.
 
   Location information identifies how one should contact a particular
   service. One or more location URIs may be included in a discovery
   response or a presence announcement.
 
   Expiration information identifies how long a SSDP client should keep
   information about the service in its cache. Once the entry has
   expired it is to be removed from the SSDP client's cache.
 
   Thus a SSDP client service cache might look like:
 
   USN URI          | Service Type URI | Expiration | Location
   -----------------|------------------|------------|------------------
   upnp:uuid:k91... | upnp:clockradio  | 3 days     | http://foo.com/cr
   -----------------|------------------|------------|------------------
   uuid:x7z...      | ms:wince         | 1 week     | http://msce/win
   -----------------|------------------|------------|------------------
 
   In the previous example both USN URIs are actually UUIDs such as
   upnp:uuid:k91d4fae-7dec-11d0-a765-00a0c91c6bf6.
An anti-cheat could possibly make an ssdp request and log the USNs on your network and blacklist them.


(16) boot UUID / bcdedit UUIDs
If you run bcdedit as admin, you'll notice there are what appears to be unique IDs in the following fields:
identifier
resumeobject
displayorder (for boot manager only, contains all the IDs of the bootloaders)

Your boot UUID is currently being retrieved by anti-cheats by ZwQuerySystemInformation SystemBootEnvironmentInformation(0x5a)

example:
Code:
void get_boot_uuid()
{
	
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;
 
	neededSize = 8 * 1024 * 1024;
 
	PSYSTEM_BOOT_ENVIRONMENT_INFORMATION pBootInfo;
 
	if (pBootInfo = (decltype(pBootInfo))ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG)) {
 
		NTSTATUS r;
		if (NT_SUCCESS(r = ZwQuerySystemInformation(SystemBootEnvironmentInformation, pBootInfo, neededSize, 0))) {
			DbgPrint("boot GUID: %08X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X\n", pBootInfo->BootIdentifier.Data1, pBootInfo->BootIdentifier.Data2, pBootInfo->BootIdentifier.Data3, pBootInfo->BootIdentifier.Data4[0], pBootInfo->BootIdentifier.Data4[1], pBootInfo->BootIdentifier.Data4[2], pBootInfo->BootIdentifier.Data4[3], pBootInfo->BootIdentifier.Data4[4], pBootInfo->BootIdentifier.Data4[5], pBootInfo->BootIdentifier.Data4[6], pBootInfo->BootIdentifier.Data4[7]);
			ExFreePoolWithTag(pBootInfo, POOL_TAG);
		}
		else
			DbgPrint("r = %x\n", r);
	}
}
(17) USN Journal IDs
I have discovered that one anti-cheat is using the USN journal ID as a HWID mechanism.
How this is done is by sending the ioctl FSCTL_QUERY_USN_JOURNAL to \\.\X: where X is the drive letter, you can retrieve a USN_JOURNAL_DATA structure which contains a
Code:
DWORDLONG UsnJournalID;
You can force a new journal ID by doing:
Code:
		system("fsutil usn deletejournal /n c:");
		system("fsutil usn deletejournal /n D:");
		system("fsutil usn deletejournal /n E:");
		system("fsutil usn deletejournal /n F:");
(11) Everything else that's not covered:

https://en.wikipedia.org/wiki/CPUID#..._Serial_Number (not implemented in newer models anymore)

steam userdata(contains your steam id64 in some files which can be used to identify you, some AC uses this) / Steam Guard ssfn files: GamersClub AC: Ban evasion detection update
etc:

Windows SIDs & your IP address can also be used to track you.
Some anti-cheats may also create tracking files/keys/system variables on your system, which will contain a unique identifier in order to identify you.

Some anti-cheats query wmi data from kernel-mode using IoWMIQueryAllData.

Code:
MoveFile(L"C:\\Windows\\System32\\spp\\store", L"C:\\Windows\\System32\\spp\\storex"); //disable slmgr /dlv (and the WMI path for it), CMID
non-unique but still queried by anti-cheats:
Code:
GPU name
processor name
disk names
network adapter names
processor features(ntoskrnl!ExIsProcessorFeaturePresent reads from 0x0FFFFF78000000274ull which anti-cheats also do)
bios vendor release #
bios vendor name
Another way to make a "hwid" is possibly by getting the hostnames of all devices on your local network (e.g. using llmnr).
