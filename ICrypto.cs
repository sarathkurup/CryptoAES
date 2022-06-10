namespace CryptoAES
{
    public interface ICrypto
    {
        /// <summary>
        /// Encrypt a String
        /// </summary> 
        /// <param name="Key" eg: "hello world"></param>
        /// <param name="InputText"></param>
        /// <returns></returns>
        string EncryptString(string Key, string InputText);

        /// <summary>
        /// Decrypt a String
        /// </summary> 
        /// <param name="Key" eg: "hello world"></param>
        /// <param name="encryptedText"></param>
        /// <returns></returns>
        string DecryptString(string Key, string encryptedText);

        /// <summary>
        /// Encrypt a File
        /// </summary> 
        /// <param name="Key" eg: "hello world"></param>
        /// <param name="InputStream"></param>
        /// <returns></returns>
        Stream EncryptFile(string Key, Stream InputStream);

        /// <summary>
        /// Decrypt a File
        /// </summary>  
        /// <param name="Key" eg: "hello world"></param>
        /// <param name="CipherStream"></param>
        /// <returns></returns>
        Stream DecryptFile(string Key, Stream CipherStream);
    }
}
