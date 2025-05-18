using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;
using System.Text;

public class GorgonKhronos0404Encryptor
{
    private static readonly byte[] KEY =
    {
        0xDF, 0x77, 0xB9, 0x40, 0xB9, 0x9B, 0x84, 0x83, 0xD1, 0xB9,
        0xCB, 0xD1, 0xF7, 0xC2, 0xB9, 0x85, 0xC3, 0xD0, 0xFB, 0xC3
    };

    public (string EncryptedData, string Timestamp, string MD5Hash) Encrypt(string paramsStr, string data, string cookies)
    {
        paramsStr = paramsStr.Split("?")[1];
        string baseStr = BuildBaseString(paramsStr, data, cookies);

        var paramList = CreateParamList(baseStr);
        var xorList = ComputeXORList(paramList);
        var result = string.Concat(xorList.Select(HexStr));
        return ($"0404b0d30000{result}", GetCurrentTimestamp(), GetMD5Hash(paramsStr));
    }

    private string BuildBaseString(string paramsStr, string data, string cookies)
    {
        return SrctHash(paramsStr) +
               SrctHash(string.IsNullOrEmpty(data) ? new string('0', 32) : data) +
               SrctHash(string.IsNullOrEmpty(cookies) ? new string('0', 32) : cookies);
    }

    private string SrctHash(string data)
    {
        using (MD5 md5 = MD5.Create())
        {
            byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(data));
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }
    }

    private List<byte> CreateParamList(string baseStr)
    {
        var paramList = new List<byte>();

        for (int i = 0; i < 12; i++)
        {
            string temp = baseStr.Substring(8 * i, 8);
            for (int j = 0; j < 4; j++)
            {
                paramList.Add(Convert.ToByte(temp.Substring(j * 2, 2), 16));
            }
        }

        paramList.AddRange(new byte[] { 0x0, 0x6, 0xB, 0x1C });
        paramList.AddRange(BitConverter.GetBytes((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds()));

        return paramList;
    }

    private List<byte> ComputeXORList(List<byte> paramList)
    {
        var xorList = paramList.Zip(KEY, (a, b) => (byte)(a ^ b)).ToList();

        for (int i = 0; i < xorList.Count; i++)
        {
            byte e = (byte)(ReverseByte(xorList[i]) ^ xorList[(i + 1) % xorList.Count]);
            xorList[i] = (byte)(((ReverseBits(e) ^ 0xFF) ^ xorList.Count) & 0xFF);
        }

        return xorList;
    }

    private byte ReverseByte(byte num)
    {
        string hexStr = num.ToString("x2");
        return Convert.ToByte(hexStr.Substring(1) + hexStr[0], 16);
    }

    private byte ReverseBits(byte num)
    {
        var binaryStr = Convert.ToString(num, 2).PadLeft(8, '0');
        return Convert.ToByte(new string(binaryStr.Reverse().ToArray()), 2);
    }

    private string GetMD5Hash(string input)
    {
        using (var md5 = MD5.Create())
        {
            var inputBytes = Encoding.UTF8.GetBytes(input);
            var hashBytes = md5.ComputeHash(inputBytes);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToUpper();
        }
    }

    private string GetCurrentTimestamp()
    {
        return DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
    }

    private string HexStr(byte num)
    {
        return num.ToString("x2");
    }
}

public static class LadonEncryption
{
    private const int blockSize = 16;

    public static string MD5Bytes(byte[] data)
    {
        using (var md5 = MD5.Create())
        {
            return BitConverter.ToString(md5.ComputeHash(data)).Replace("-", "").ToLower();
        }
    }

    public static ulong GetTypeData(byte[] ptr, int index)
    {
        return BitConverter.ToUInt64(ptr, index * 8);
    }

    public static void SetTypeData(byte[] ptr, int index, ulong data)
    {
        byte[] bytes = BitConverter.GetBytes(data);
        Array.Copy(bytes, 0, ptr, index * 8, bytes.Length);
    }

    public static ulong ROR(ulong value, int count)
    {
        int nbits = sizeof(ulong) * 8;
        count %= nbits;
        ulong low = value << (nbits - count);
        value >>= count;
        value |= low;
        return value;
    }

    public static byte[] EncryptLadonInput(byte[] hashTable, byte[] inputData)
    {
        ulong data0 = BitConverter.ToUInt64(inputData, 0);
        ulong data1 = BitConverter.ToUInt64(inputData, 8);

        for (int i = 0; i < 0x22; i++)
        {
            ulong hash = BitConverter.ToUInt64(hashTable, i * 8);
            data1 = hash ^ (data0 + ((data1 >> 8) | (data1 << (64 - 8))));
            data0 = data1 ^ ((data0 >> 0x3D) | (data0 << (64 - 0x3D)));
        }

        byte[] outputData = new byte[16];
        BitConverter.GetBytes(data0).CopyTo(outputData, 0);
        BitConverter.GetBytes(data1).CopyTo(outputData, 8);

        return outputData;
    }
    public static void PKCS7PaddingPadBuffer(byte[] buffer, int originalSize, int paddedSize)
    {
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));

        if (originalSize > paddedSize)
            throw new ArgumentException("Original size cannot be greater than padded size.");

        byte paddingValue = (byte)(paddedSize - originalSize);
        for (int i = originalSize; i < paddedSize; i++)
        {
            buffer[i] = paddingValue;
        }
    }
    public static int PaddingSize(int size)
    {
        int blockSize = 16;
        int remainder = size % blockSize;
        if (remainder == 0)
            return size;

        return size + (blockSize - remainder);
    }


    public static byte[] EncryptLadon(string md5Hex, string data, int size)
    {
        byte[] hashTable = new byte[288];
        byte[] md5Bytes = Encoding.ASCII.GetBytes(md5Hex);
        Array.Copy(md5Bytes, hashTable, 32);

        ulong[] temp = new ulong[4];
        for (int i = 0; i < 4; i++)
        {
            temp[i] = GetTypeData(hashTable, i);
        }

        ulong bufferB0 = temp[0];
        ulong bufferB8 = temp[1];
        temp = new ulong[] { temp[2], temp[3] };

        for (int i = 0; i < 0x22; i++)
        {
            ulong x9 = bufferB0;
            ulong x8 = bufferB8;
            x8 = ROR(x8, 8);
            x8 += x9;
            x8 ^= (ulong)i;
            Array.Resize(ref temp, temp.Length + 1);
            temp[temp.Length - 1] = x8;
            x8 ^= ROR(x9, 61);
            SetTypeData(hashTable, i + 1, x8);
            bufferB0 = x8;
            bufferB8 = temp[0];
            temp = new ulong[] { temp[1] };
        }

        int newSize = PaddingSize(size);
        byte[] inputData = new byte[newSize];
        Array.Copy(Encoding.ASCII.GetBytes(data), inputData, size);
        PKCS7PaddingPadBuffer(inputData, size, newSize);

        byte[] output = new byte[newSize];
        for (int i = 0; i < newSize / blockSize; i++)
        {
            byte[] encryptedBlock = EncryptLadonInput(hashTable, inputData.Skip(i * blockSize).Take(blockSize).ToArray());
            Array.Copy(encryptedBlock, 0, output, i * blockSize, blockSize);
        }

        return output;
    }

    public static string LadonEncrypt(int khronos, int lcId = 1611921764, int aid = 1233, byte[] randomBytes = null)
    {
        if (randomBytes == null)
        {
            randomBytes = new byte[4];
            RandomNumberGenerator.Fill(randomBytes);
        }

        string data = $"{khronos}-{lcId}-{aid}";
        byte[] keygen = new byte[randomBytes.Length + sizeof(int)];
        Array.Copy(randomBytes, keygen, randomBytes.Length);
        BitConverter.GetBytes(aid).CopyTo(keygen, randomBytes.Length);
        string md5hex = MD5Bytes(keygen);

        int size = Encoding.ASCII.GetByteCount(data);
        int newSize = PaddingSize(size);

        byte[] output = new byte[newSize + 4];
        Array.Copy(randomBytes, output, 4);

        byte[] encrypted = EncryptLadon(md5hex, data, size);
        Array.Copy(encrypted, 0, output, 4, encrypted.Length);

        return Convert.ToBase64String(output);
    }

}

public class SimonCipher
{
    private const int WORD_SZ = 64;
    private const int T = 72;
    private const int M = 4;
    private const ulong Z_SEQUENCE = 0x3DC94C3A046D678B;

    // Private helper to get specific bit from value
    private static ulong GetBit(ulong value, int position)
    {
        return (value & (1UL << position)) > 0 ? 1UL : 0;
    }

    // Private helper to rotate value left by num positions
    private static ulong RotateLeft(ulong value, int num)
    {
        return (value << num) | (value >> (WORD_SZ - num));
    }

    // Key expansion for Simon Cipher
    private static void KeyExpansion(ulong[] key)
    {
        ulong temp;

        for (int i = M; i < T; i++)
        {
            temp = RotateLeft(key[i - 1], 3);
            temp ^= key[i - 3];
            temp ^= RotateLeft(temp, 1);
            key[i] = ~key[i - M] ^ temp ^ GetBit(Z_SEQUENCE, (i - M) % 62) ^ 3;
        }
    }

    // Function for the forward round in the Simon Cipher
    private static void ForwardRound(ulong[] plaintext, ulong[] ciphertext, ulong[] key)
    {
        var roundKey = new ulong[T];
        Array.Copy(key, roundKey, key.Length);
        KeyExpansion(roundKey);

        ulong x_i = plaintext[0];
        ulong x_i1 = plaintext[1];

        for (int i = 0; i < T; i++)
        {
            ulong tmp = x_i1;
            ulong f = RotateLeft(x_i1, 1) ^ RotateLeft(x_i1, 8);
            x_i1 = x_i ^ f ^ RotateLeft(x_i1, 2) ^ roundKey[i];
            x_i = tmp;
        }

        ciphertext[0] = x_i;
        ciphertext[1] = x_i1;
    }

    // Public method to encrypt plaintext using Simon Cipher
    public static byte[] Encrypt(byte[] plaintextBytes, byte[] keyBytes)
    {
        ulong[] plaintext = new ulong[2];
        Buffer.BlockCopy(plaintextBytes, 0, plaintext, 0, 16);

        ulong[] key = new ulong[4];
        Buffer.BlockCopy(keyBytes, 0, key, 0, 32);

        ulong[] ciphertext = new ulong[2];
        ForwardRound(plaintext, ciphertext, key);

        byte[] output = new byte[16];
        Buffer.BlockCopy(ciphertext, 0, output, 0, 16);

        return output;
    }
}

public class ArgusEncryptor
{
    private const int BLOCK_SIZE = 16;
    private static readonly string BASE64_KEY = "jr36OAbsxc7nlCPmAp7YJUC8Ihi7fq73HLaR96qKovU=";

    public static string Encrypt(byte[] protobuf, uint protobufSize)
    {
        uint randomNum = GenerateRandomNumber();

        byte[] signKey = Convert.FromBase64String(BASE64_KEY);
        byte[] sm3Output = CalculateSM3Digest(signKey, randomNum);

        byte[] paddedProtobuf = PadProtobuf(protobuf, protobufSize);

        for (int i = 0; i < paddedProtobuf.Length / BLOCK_SIZE; i++)
        {
            byte[] plaintextBlock = new byte[BLOCK_SIZE];
            Array.Copy(paddedProtobuf, i * BLOCK_SIZE, plaintextBlock, 0, BLOCK_SIZE);

            byte[] ciphertextBlock = SimonCipher.Encrypt(plaintextBlock, sm3Output);

            Array.Copy(ciphertextBlock, 0, paddedProtobuf, i * BLOCK_SIZE, BLOCK_SIZE);
        }

        return Convert.ToBase64String(paddedProtobuf);
    }

    private static uint GenerateRandomNumber()
    {
        return (uint)new Random().Next(10000000, 99999999);
    }

    private static byte[] CalculateSM3Digest(byte[] signKey, uint randomNum)
    {
        int size = signKey.Length * 2 + sizeof(uint);
        byte[] sm3Input = new byte[size];

        Array.Copy(signKey, 0, sm3Input, 0, signKey.Length);
        Array.Copy(BitConverter.GetBytes(randomNum), 0, sm3Input, signKey.Length, sizeof(uint));
        Array.Copy(signKey, 0, sm3Input, signKey.Length + sizeof(uint), signKey.Length);

        var sm3Output = new byte[32];
        var sm3 = new SM3Digest();
        sm3.BlockUpdate(sm3Input, 0, sm3Input.Length);
        sm3.DoFinal(sm3Output, 0);

        return sm3Output;
    }

    private static byte[] PadProtobuf(byte[] protobuf, uint protobufSize)
    {
        int paddedSize = GetPaddedSize(protobufSize);
        byte[] paddedProtobuf = new byte[paddedSize];
        Array.Copy(protobuf, paddedProtobuf, protobufSize);
        ApplyPKCS7Padding(paddedProtobuf, protobufSize, paddedSize);
        return paddedProtobuf;
    }

    private static int GetPaddedSize(uint size)
    {
        int modSize = (int)size % BLOCK_SIZE;
        return modSize > 0 ? (int)size + BLOCK_SIZE - modSize : (int)size;
    }

    private static void ApplyPKCS7Padding(byte[] buffer, uint originalSize, int paddedSize)
    {
        int paddingSize = paddedSize - (int)originalSize;
        for (int i = 0; i < paddingSize; i++)
        {
            buffer[originalSize + i] = (byte)paddingSize;
        }
    }
}