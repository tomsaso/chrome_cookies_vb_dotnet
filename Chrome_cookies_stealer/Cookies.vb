Imports System.IO
Imports System.Data.SQLite
Imports System.Text
Imports System.Environment
Imports Newtonsoft.Json.Linq
Imports Org.BouncyCastle.Crypto
Imports System.Security.Cryptography
Imports Org.BouncyCastle.Crypto.Parameters
Imports Org.BouncyCastle.Crypto.Modes
Imports Org.BouncyCastle.Crypto.Engines
Imports System.Text.RegularExpressions
Module Cookies

    Public Function GetChromeCookiePath() As String
        Dim s As String = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        s += "\Google\Chrome\User Data\Default\Cookies"
        If Not File.Exists(s) Then Return String.Empty
        File.Copy(s, "cookie-temp", True)
        Return "cookie-temp"
    End Function

    Public Function GetCookieJar(domain_host As String) As Dictionary(Of String, String)
        Dim desiredCookies = {".DATPOWERAUTH"}
        Dim strPath, strDb As String
        Dim CookiesDict As Dictionary(Of String, String) = New Dictionary(Of String, String)
        Dim enc_key As Byte()
        enc_key = GetEncKey()
        strPath = Cookies.GetChromeCookiePath()
        strDb = "Data Source=" & strPath & ";"
        Dim conn As SQLiteConnection = New SQLiteConnection(strDb)
        Dim cmd As SQLiteCommand = conn.CreateCommand()
        cmd.CommandText = "SELECT name, encrypted_value FROM cookies WHERE host_key LIKE %" + domain_host + "%"
        conn.Open()

        Using reader As SQLiteDataReader = cmd.ExecuteReader()
            While reader.Read()
                Dim name = reader.GetString(0)
                If desiredCookies.Contains(name) Then
                    Dim bajt() As Byte = reader.GetValue(1)
                    Dim Value As String = _decryptWithKey(bajt, enc_key, 3)
                    CookiesDict.Add(name, Value)
                End If
            End While
        End Using

        conn.Close()
        Return CookiesDict

        'Dim encoded = New List(Of String)
        'For Each cookie In CookiesDict
        '    Dim part = cookie.Key & "=" & cookie.Value
        '    encoded.Add(part)
        'Next
        'Return String.Join("; ", encoded)
    End Function

    Public Function _decryptWithKey(ByVal message As Byte(), ByVal key As Byte(), ByVal nonSecretPayloadLength As Integer) As String
        ' Dim message As Byte()
        ' message = UnicodeStringToBytes(message1)
        ' key = UnicodeStringToBytes(key1)
        Const KEY_BIT_SIZE As Integer = 256
        Const MAC_BIT_SIZE As Integer = 128
        Const NONCE_BIT_SIZE As Integer = 96
        If key Is Nothing OrElse key.Length <> KEY_BIT_SIZE / 8 Then Throw New ArgumentException(String.Format("Key needs to be {0} bit!", KEY_BIT_SIZE), "key")
        If message Is Nothing OrElse message.Length = 0 Then Throw New ArgumentException("Message required!", "message")

        Using cipherStream = New MemoryStream(message)

            Using cipherReader = New BinaryReader(cipherStream)
                Dim nonSecretPayload = cipherReader.ReadBytes(nonSecretPayloadLength)
                Dim nonce = cipherReader.ReadBytes(NONCE_BIT_SIZE / 8)
                Dim cipher = New GcmBlockCipher(New AesEngine())
                Dim parameters = New AeadParameters(New KeyParameter(key), MAC_BIT_SIZE, nonce)
                cipher.Init(False, parameters)
                Dim cipherText = cipherReader.ReadBytes(message.Length)
                Dim plainText = New Byte(cipher.GetOutputSize(cipherText.Length) - 1) {}

                Try
                    Dim len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0)
                    cipher.DoFinal(plainText, len)
                Catch __unusedInvalidCipherTextException1__ As InvalidCipherTextException
                    Return Nothing
                End Try

                Return Encoding.[Default].GetString(plainText)
            End Using
        End Using
    End Function
    Private Function UnicodeStringToBytes(
        ByVal str As String) As Byte()

        Return Encoding.Unicode.GetBytes(str)
    End Function

    Public Function GetEncKey() As Byte()
        Dim appData As String = GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        Dim keyfile As String
        Console.Write(appData)
        keyfile = appData & "\Google\Chrome\User Data\Local State"
        Dim encKey As String
        encKey = File.ReadAllText(keyfile)
        Dim jsoc As JObject
        jsoc = JObject.Parse(encKey)
        Dim vvv
        vvv = jsoc("os_crypt")("encrypted_key")
        Dim the_key As String
        the_key = vvv.ToString()
        Dim decodedKey = ProtectedData.Unprotect(Convert.FromBase64String(the_key).Skip(5).ToArray(), Nothing, DataProtectionScope.LocalMachine)

        Return decodedKey
    End Function
End Module