using FileAttributes = SMBLibrary.FileAttributes;

namespace <#= ProjectNamespace #>.Models
{
	/// <summary>
    /// 存取網芳的工具類別
    /// </summary>
    internal class SMBClient
    {
        ISMBClient _client;

        ILogger Logger { get; set; }

        private NTStatus _status;
        private FileStatus _fileStatus;
        /// <summary>
        /// 取得或設定操作結果
        /// </summary>
        public NTStatus Status => _status;

        /// <summary>
        /// 取得或設定檔案操作狀態
        /// </summary>
        public FileStatus FileStatus => _fileStatus;

        /// <summary>
        /// 取得或設定傳輸類型
        /// </summary>
        public SMBTransportType TransportType { get; set; }

        /// <summary>
        /// 取得目前連結的伺服器IP資訊
        /// </summary>
        public IPAddress Host { get; private set; }

        /// <summary>
        /// 建構式
        /// </summary>
        public SMBClient(ILogger<SMBClient> logger)
        {
            //使用SMBv2協定，因v1有安全性漏洞問題目前微軟已關閉v1協定使用
            _client = new SMB2Client();
            Host = IPAddress.None;
            TransportType = SMBTransportType.DirectTCPTransport;
            Logger = logger;
        }

        /// <summary>
        /// 連結到指定伺服器
        /// </summary>
        /// <param name="host">主機IP位址</param>
        /// <returns>成功傳回 True ，失敗則傳回 False。</returns>
        public bool ConnectToServer(IPAddress host)
        {
            try
            {
                Host = host;

                bool result = _client.Connect(Host, TransportType);

                string HostName = string.Empty;

                try
                {
                    HostName = Dns.GetHostEntry(host).HostName;
                }
                catch (Exception ex)
                {
                    HostName = host.ToString();
                    WriteAuditTrailLog(Language.Phrase(Config.LanguageCodes.error_9999_0002).Replace("%s",ex.Message).Replace("%stacktrace", ex.StackTrace))
                        .GetAwaiter().GetResult();
                }

                if (result)
                {
                    Logger.LogInformation($"連接檔案伺服器{HostName}連結成功!");
                }
                else
                {
                    Logger.LogInformation($"連接檔案伺服器{HostName}連結失敗!");
                }

                return result;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, null);
                return false;
            }
        }

        /// <summary>
        /// 連結到指定伺服器
        /// </summary>
        /// <param name="iporhostname">主機名稱或IP位址</param>
        /// <returns>成功傳回 True ，失敗則傳回 False。</returns>
        public bool ConnectToServer(string iporhostname)
        {
            try
            {
                if (!iporhostname.IsIpAddress())
                {
                    iporhostname = Dns.GetHostEntry(iporhostname).AddressList.FirstOrDefault()?.ToString() ?? throw new Exception($"無法查詢 {iporhostname} 的IP位址!");
                }

                Host = IPAddress.Parse(iporhostname);

                return ConnectToServer(IPAddress.Parse(iporhostname));
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, null);
                return false;
            }
        }

        /// <summary>
        /// 登入遠端伺服器
        /// </summary>
        /// <param name="LoginUserName">帳號名稱</param>
        /// <param name="LoginPassword">登入密碼</param>
        /// <param name="domainName">網域名稱(如果是在AD環境下，此參數必填)</param>
        /// <returns>成功傳回 True ，失敗則傳回 False。</returns>
        public bool Login(string LoginUserName, string LoginPassword, string domainName = "")
        {
            try
            {
                string HostName = string.Empty;

                try
                {
                    HostName = Dns.GetHostEntry(Host).HostName;
                }
                catch (Exception ex)
                {
                    HostName = Host.ToString();
                    WriteAuditTrailLog(Language.Phrase(Config.LanguageCodes.error_9999_0002).Replace("%s", ex.Message).Replace("%stacktrace", ex.StackTrace))
                        .GetAwaiter().GetResult();
                }

                string userDisplayname;

                if (!Empty(domainName))
                    userDisplayname = $"{domainName}\\{LoginUserName}";
                else
                    userDisplayname = LoginUserName;

                Logger.LogInformation($"登入檔案伺服器{HostName}(登入帳號{userDisplayname})...");

                _status = _client.Login(domainName, LoginUserName, LoginPassword);

                if (Status == NTStatus.STATUS_SUCCESS)
                {
                    Logger.LogInformation($"登入檔案伺服器{HostName}成功!(登入帳號{userDisplayname})");
                    return true;
                }
                else
                {
                    Logger.LogInformation($"登入檔案伺服器{HostName}失敗!(登入帳號{userDisplayname})");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, null);
                return false;
            }

        }

        /// <summary>
        /// 從伺服器登出
        /// </summary>
        public void Logout()
        {
            _status = _client.Logoff();
        }

        /// <summary>
        /// 中斷與伺服器連線
        /// </summary>
        public void Disconnect()
        {
            try
            {
                if (Empty(_client) == false)
                    _client.Disconnect();
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, null);
            }
        }

        /// <summary>
        /// 列出遠端伺服器的分享資料夾清單
        /// </summary>
        /// <returns>傳回遠端分享資料夾字串集合</returns>
        public List<string> ListAllShareFolders()
        {
            try
            {
                List<string> remotefolder = new List<string>();

                List<string> shares = _client.ListShares(out _status);

                if (_status == NTStatus.STATUS_SUCCESS && shares.Count > 0)
                {
                    remotefolder.AddRange(shares);
                }

                return remotefolder;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, null);
                return new();
            }
        }

        /// <summary>
        /// 列出指定分享資料夾的檔案和子目錄清單
        /// </summary>
        /// <param name="shareName">分享資源名稱</param>
        /// <param name="remotefolder">資料夾名稱</param>        
        /// <returns></returns>
        public List<string> ListAllFilesInRemoteFolder(string shareName, string remotefolder = "")
        {
            try
            {
                List<string> filesInRemoteFolder = new List<string>();

                if (Empty(shareName))
                {
                    return new();
                }

                ISMBFileStore fileStore = _client.TreeConnect(shareName, out _status);

                if (Status == NTStatus.STATUS_SUCCESS)
                {
                    object directoryHandle;
                    _status = fileStore.CreateFile(out directoryHandle, out _fileStatus, remotefolder, AccessMask.GENERIC_READ, FileAttributes.Directory, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);

                    if (Status == NTStatus.STATUS_SUCCESS)
                    {
                        List<QueryDirectoryFileInformation> fileList;

                        _status = fileStore.QueryDirectory(out fileList, directoryHandle, "*", FileInformationClass.FileDirectoryInformation);

                        if (!Empty(fileList) && fileList.Any())
                        {
                            foreach (FileDirectoryInformation f in fileList)
                            {
                                filesInRemoteFolder.Add(f.FileName);
                                Logger.LogInformation("找到檔案或目錄 {0}", f.FileName);
                            }
                        }

                        _status = fileStore.CloseFile(directoryHandle);
                    }
                }

                return filesInRemoteFolder;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, null);
                return new();
            }

        }

        /// <summary>
        /// 從共用位置讀取檔案
        /// </summary>
        /// <param name="shareName">共享位置名稱(遠端資料夾路徑)</param>
        /// <param name="filePath">檔案名稱</param>
        /// <returns>成功傳回檔案內容</returns>
        /// <exception cref="Exception"></exception>
        public byte[] ReadFile(string shareName, string filePath)
        {
            ISMBFileStore fileStore = _client.TreeConnect(shareName, out _status);

            object fileHandle;
            if (_status != NTStatus.STATUS_SUCCESS)
            {
                throw new Exception("Failed to connect to share");
            }
            //string filePath = "IMG_20190109_174446.jpg";

            if (fileStore is SMB1FileStore)
            {
                filePath = @"\\" + filePath;
            }

            _status = fileStore.CreateFile(out fileHandle, out _fileStatus, filePath, AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE, FileAttributes.Normal, ShareAccess.Read, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);

            if (Empty(fileStore))
            {
                return new byte[] { };
            }

            MemoryStream stream = new MemoryStream();

            if (Status == NTStatus.STATUS_SUCCESS)
            {
                byte[] buffer;
                long bytesRead = 0;

                while (true)
                {
                    _status = fileStore.ReadFile(out buffer, fileHandle, bytesRead, (int)_client.MaxReadSize);
                    if (_status != NTStatus.STATUS_SUCCESS && Status != NTStatus.STATUS_END_OF_FILE)
                    {
                        throw new Exception("Failed to read from file");
                    }

                    if (_status == NTStatus.STATUS_END_OF_FILE || buffer.Length == 0)
                    {
                        break;
                    }
                    bytesRead += buffer.Length;
                    stream.Write(buffer, 0, buffer.Length);
                }
            }

            _status = fileStore.CloseFile(fileHandle);
            _status = fileStore.Disconnect();

            return stream.ToArray();
        }

        /// <summary>
        /// 在共享位置上建立檔案
        /// </summary>
        /// <param name="shareName">共享位置名稱(遠端資料夾路徑)</param>
        /// <param name="filePath">檔案名稱</param>
        /// <param name="content">要寫入的二進位內容</param>
        /// <exception cref="Exception"></exception>
        public void CreateFile(string shareName, string filePath, byte[] content)
        {
            ISMBFileStore fileStore = _client.TreeConnect(shareName, out _status);
            if (_status != NTStatus.STATUS_SUCCESS)
            {
                throw new Exception("Failed to connect to share");
            }
            //string localFilePath = @"C:\Image.jpg";
            //string remoteFilePath = "NewFile.jpg";
            if (fileStore is SMB1FileStore)
            {
                filePath = @"\\" + filePath;
            }
            //MemoryStream localFileStream = new MemoryStream(content);
            object fileHandle;
            FileStatus fileStatus;
            _status = fileStore.CreateFile(out fileHandle, out fileStatus, filePath, AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE, FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_CREATE, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
            if (_status == NTStatus.STATUS_SUCCESS)
            {
                int writeOffset = 0;
                //byte[] buffer = new byte[(int)_client.MaxWriteSize];
                //int bytesRead = localFileStream.Read(content, 0, content.Length);
                //if (bytesRead < (int)_client.MaxWriteSize)
                //{
                //    Array.Resize<byte>(ref content, bytesRead);
                //}
                int numberOfBytesWritten;
                _status = fileStore.WriteFile(out numberOfBytesWritten, fileHandle, writeOffset, content);
                if (_status != NTStatus.STATUS_SUCCESS)
                {
                    throw new Exception("Failed to write to file");
                }

                //while (localFileStream.Position < localFileStream.Length)
                //{
                    
                //    writeOffset += bytesRead;
                //}
                _status = fileStore.CloseFile(fileHandle);
            }
            _status = fileStore.Disconnect();
        }

        public bool DeleteFile(string shareName, string filePath)
        {
            ISMBFileStore fileStore = _client.TreeConnect(shareName, out _status);
            //string filePath = "DeleteMe.txt";
            if (fileStore is SMB1FileStore)
            {
                filePath = @"\\" + filePath;
            }
            object fileHandle;
            FileStatus fileStatus;
            _status = fileStore.CreateFile(out fileHandle, out fileStatus, filePath, AccessMask.GENERIC_WRITE | AccessMask.DELETE | AccessMask.SYNCHRONIZE, FileAttributes.Normal, ShareAccess.None, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);

            if (_status == NTStatus.STATUS_SUCCESS)
            {
                FileDispositionInformation fileDispositionInformation = new FileDispositionInformation();
                fileDispositionInformation.DeletePending = true;
                _status = fileStore.SetFileInformation(fileHandle, fileDispositionInformation);
                bool deleteSucceeded = (_status == NTStatus.STATUS_SUCCESS);
                _status = fileStore.CloseFile(fileHandle);
            }
            _status = fileStore.Disconnect();
            return true;
        }
    }
}