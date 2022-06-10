# CryptoAES
 AES Encryption Decryption (Cryptography) Text or File
 
Eg: Key = "Hello World"

    string EncryptString(string Key, string InputText);
    string DecryptString(string Key, string encryptedText);
    Stream EncryptFile(string Key, Stream InputStream);
    Stream DecryptFile(string Key, Stream CipherStream);



# Nuget
https://www.nuget.org/packages/CryptoAES/

     Package Reference : <PackageReference Include="CryptoAES"/>
       Package Manager : Install-Package CryptoAES
              .NET CLI : dotnet add package CryptoAES
            Packet CLI : paket add CryptoAES
    Script&Interactive : #r "nuget: CryptoAES"
            Cake Addin : #addin nuget:?package=CryptoAES
             Cake Tool : #tool nuget:?package=CryptoAES
