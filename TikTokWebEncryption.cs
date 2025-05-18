using System;
using System.Security.Cryptography;
using System.Text;

public class XBogus
{
    public static byte[] Md5Enc(byte[] data)
    {
        using (var md5 = MD5.Create())
        {
            return md5.ComputeHash(data);
        }
    }

    public static byte[] Rc4Enc(byte[] key, byte[] plaintext)
    {
        var cipher = new RC4(key);
        return cipher.Transform(plaintext);
    }

    public static byte XorVerify(byte[] list)
    {
        byte num = 0;
        foreach (var val in list)
        {
            num ^= val;
        }
        return num;
    }

    public static string Encode(string parameters, string data, string userAgent, uint timestamp)
    {
        var Base64 = new CustomBase64Encoding("Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe");
        byte[] uaKey = { 0, 1, 14 };
        byte[] listKey = { 255 };
        uint fixedValue = 3845494467;

        byte[] md5Params = Md5Enc(Md5Enc(Encoding.UTF8.GetBytes(parameters)));
        byte[] md5Data = Md5Enc(Md5Enc(Encoding.UTF8.GetBytes(data)));
        byte[] md5UA = Md5Enc(Encoding.UTF8.GetBytes(Convert.ToBase64String(Rc4Enc(uaKey, Encoding.UTF8.GetBytes(userAgent)))));

        byte[] list = new byte[19];
        int pos = 0;
        list[pos++] = 64;
        Array.Copy(uaKey, 0, list, pos, uaKey.Length);
        pos += uaKey.Length;
        list[pos++] = md5Params[14];
        list[pos++] = md5Params[15];
        list[pos++] = md5Data[14];
        list[pos++] = md5Data[15];
        list[pos++] = md5UA[14];
        list[pos++] = md5UA[15];
        Array.Copy(BitConverter.GetBytes(timestamp), 0, list, pos, 4);
        pos += 4;
        Array.Copy(BitConverter.GetBytes(fixedValue), 0, list, pos, 4);
        pos += 4;
        list[pos] = XorVerify(list);

        byte[] enc = new byte[21];
        enc[0] = 2;
        enc[1] = listKey[0];
        Array.Copy(Rc4Enc(listKey, list), 0, enc, 2, 19);

        return Base64.Encode(enc);
    }

    public static XBogusInfo Decode(string xb)
    {
        var Base64 = new CustomBase64Encoding("Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe");
        byte[] decoded = Base64.Decode(xb);
        if (decoded.Length != 21)
            throw new Exception("XB string length is not 21");

        byte[] data = Rc4Enc(new byte[] { 255 }, decoded[2..]);
        return new XBogusInfo
        {
            Logo = data[0],
            Key = data[1..4],
            ParamsHash = data[4..6],
            DataHash = data[6..8],
            UAHash = data[8..10],
            Ts = BitConverter.ToUInt32(data, 10),
            Fixed = BitConverter.ToUInt32(data, 14),
            XorHash = data[18]
        };
    }
}
public class CustomBase64Encoding
{
    private readonly Dictionary<char, char> encodeMap = new Dictionary<char, char>();
    private readonly Dictionary<char, char> decodeMap = new Dictionary<char, char>();

    public CustomBase64Encoding(string customDictionary)
    {
        if (customDictionary.Length != 64)
            throw new ArgumentException("Custom dictionary must be exactly 64 characters long.");

        string standardBase64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        for (int i = 0; i < 64; i++)
        {
            encodeMap[standardBase64Chars[i]] = customDictionary[i];
            decodeMap[customDictionary[i]] = standardBase64Chars[i];
        }
    }

    public string Encode(byte[] data)
    {
        string standardBase64 = Convert.ToBase64String(data);

        StringBuilder customBase64 = new StringBuilder(standardBase64.Length);
        foreach (char c in standardBase64)
        {
            if (c == '=')
            {
                customBase64.Append(c); // Preserve padding
            }
            else
            {
                customBase64.Append(encodeMap[c]);
            }
        }

        return customBase64.ToString();
    }

    public byte[] Decode(string customBase64)
    {
        StringBuilder standardBase64 = new StringBuilder(customBase64.Length);
        foreach (char c in customBase64)
        {
            if (c == '=')
            {
                standardBase64.Append(c); // Preserve padding
            }
            else
            {
                standardBase64.Append(decodeMap[c]);
            }
        }

        return Convert.FromBase64String(standardBase64.ToString());
    }
}

public class XBogusInfo
{
    public byte Logo { get; set; }
    public byte[] Key { get; set; }
    public byte[] ParamsHash { get; set; }
    public byte[] DataHash { get; set; }
    public byte[] UAHash { get; set; }
    public uint Ts { get; set; }
    public uint Fixed { get; set; }
    public byte XorHash { get; set; }
}

public class RC4
{
    private byte[] s;
    private int i, j;

    public RC4(byte[] key)
    {
        s = new byte[256];
        for (int k = 0; k < 256; k++)
            s[k] = (byte)k;

        int klen = key.Length;
        int j = 0;
        for (int k = 0; k < 256; k++)
        {
            j = (j + s[k] + key[k % klen]) % 256;
            (s[k], s[j]) = (s[j], s[k]);
        }
        this.i = 0;
        this.j = 0;
    }

    public byte[] Transform(byte[] data)
    {
        byte[] output = new byte[data.Length];
        for (int k = 0; k < data.Length; k++)
        {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            (s[i], s[j]) = (s[j], s[i]);
            byte kstream = s[(s[i] + s[j]) % 256];
            output[k] = (byte)(data[k] ^ kstream);
        }
        return output;
    }
}
