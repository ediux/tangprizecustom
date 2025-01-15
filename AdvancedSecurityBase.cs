<#
	args.code = "";
#>
<## Common config #>
<#= include('shared/config-common.cs') #>

<## Model class begin #>
<#= include('shared/model-class-begin.cs') #>

    /// <summary>
    /// Advanced Security class
    /// </summary>
    public class AdvancedSecurityBase
    {
        private List<UserLevel> UserLevel = new ();
        private List<UserLevelPermission> UserLevelPriv = new ();
        public List<int> UserLevelID = new ();
        public List<string> UserID = new ();
        public List<string> ParentUserID = new ();
        public string CurrentUserLevelID;
        public int CurrentUserLevel;
        public string CurrentUserID;
        public List<Claim> Claims = new (); // DN
        <# if (isDynamicUserLevel) { #>
        protected bool AnoymousUserLevelChecked = false; // Dynamic User Level security
        <# } #>
        private bool _isLoggedIn;
        private bool _isSysAdmin;
        private string _userName = "";

        // Init
        public AdvancedSecurityBase()
        {

            // User table
            <# if (hasUserTable) { // DN #>
            UserTable = Resolve("usertable")!;
            <# } #>

            // Init User Level
            if (IsLoggedIn) {
                CurrentUserLevelID = SessionUserLevelID;
                if (CurrentUserLevelID == "")
                    CurrentUserLevelID = "-2";
                SetUserLevelID(CurrentUserLevelID);
            } else { // Anonymous user
                CurrentUserLevelID = "-2";
                UserLevelID.Add(Convert.ToInt32(CurrentUserLevelID));
            }
            Session[Config.SessionUserLevelList] = UserLevelList();

            // Init User ID
            CurrentUserID = ConvertToString(SessionUserID);
            SetParentUserID(ConvertToString(SessionParentUserID));

            // Load user level
            LoadUserLevel();
        }

        // Session User ID
        protected object SessionUserID {
            get => Session.TryGetValue(Config.SessionUserId, out string? userId) ? userId : CurrentUserID;
            set {
                CurrentUserID = ConvertToString(value).Trim();
                Session[Config.SessionUserId] = CurrentUserID;
            }
        }

        // Session parent User ID
        protected object SessionParentUserID {
            get => Session.TryGetValue(Config.SessionParentUserId, out string? parentUserId) ? parentUserId : CurrentParentUserID; // DN
            set {
                SetParentUserID(ConvertToString(value).Trim());
                Session[Config.SessionParentUserId] = CurrentParentUserID; // DN
            }
        }

        // Current Parent User ID
        public string CurrentParentUserID => String.Join(Config.MultipleOptionSeparator, ParentUserID);

        // Set Parent User ID to array
        protected void SetParentUserID(object v) {
            var ids = v switch {
                List<string> list => list,
                int i => new List<string> { ConvertToString(i) },
                string str => str.Split(Config.MultipleOptionSeparator).ToList(),
                _ => new List<string>()
            };
            ParentUserID = ids;
        }

        // Check if Parent User ID in array
        public bool HasParentUserID(object v)
        {
            var ids = v switch {
                List<string> list => list,
                int i => new List<string> { ConvertToString(i) },
                string str => str.Split(Config.MultipleOptionSeparator).ToList(),
                _ => new List<string>()
            };
            return ParentUserID.Intersect(ids).Any();
        }

        // Current user name
        public string CurrentUserName
        {
            get => Session.TryGetValue(Config.SessionUserName, out string? currentUserName) ? currentUserName : _userName;
            set {
                _userName = ConvertToString(value).Trim();
                Session[Config.SessionUserName] = _userName;
            }
        }

        // Session User Level ID
        protected string SessionUserLevelID {
            get => Session.TryGetValue(Config.SessionUserLevelId, out string? userLevelId) ? userLevelId : CurrentUserLevelID;
            set {
                CurrentUserLevelID = value;
                Session.SetString(Config.SessionUserLevelId, CurrentUserLevelID);
                SetUserLevelID(CurrentUserLevelID);
            }
        }

        // Set User Level ID to array
        protected void SetUserLevelID(object v) {
            var ids = v switch {
                List<int> list => list,
                int i => new List<int> { i },
                string str => str.Split(Config.MultipleOptionSeparator).Where(x => int.TryParse(x, out _)).Select(int.Parse).ToList(),
                _ => new List<int>()
            };
            UserLevelID = ids.Where(id => id >= -2).ToList();
        }

        // Check if User Level ID in array
        public bool HasUserLevelID(object v)
        {
            var ids = v switch {
                List<int> list => list,
                int i => new List<int> { i },
                string str => str.Split(Config.MultipleOptionSeparator).Where(x => int.TryParse(x, out _)).Select(int.Parse).ToList(),
                _ => new List<int>()
            };
            return UserLevelID.Intersect(ids).Any();
        }

        // Session User Level value
        protected int SessionUserLevel {
            get => Session.TryGetValue(Config.SessionUserLevel, out string? userLevel) ? Convert.ToInt32(userLevel) : CurrentUserLevel;
            set {
                CurrentUserLevel = value;
                Session.SetString(Config.SessionUserLevel, ConvertToString(CurrentUserLevel));
            }
        }

        // Get JWT Token
        public string JwtToken =>
            GetJwtToken(CurrentUserName, ConvertToString(SessionUserID), ConvertToString(SessionParentUserID), SessionUserLevelID);

        // Get JWT Token
        public string CreateJwtToken(int expire = 0, int permission = 0) =>
            GetJwtToken(CurrentUserName, ConvertToString(SessionUserID), ConvertToString(SessionParentUserID), SessionUserLevelID, expire, permission);

        // Can add
        public bool CanAdd
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Add);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Add;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Add;
                }
            }
        }

        // Can delete
        public bool CanDelete
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Delete);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Delete;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Delete;
                }
            }
        }

        // Can edit
        public bool CanEdit
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Edit);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Edit;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Edit;
                }
            }
        }

        // Can view
        public bool CanView
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.View);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.View;
                } else {
                    CurrentUserLevel &= ~(int)Allow.View;
                }
            }
        }

        // Can list
        public bool CanList
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.List);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.List;
                } else {
                    CurrentUserLevel &= ~(int)Allow.List;
                }
            }
        }

        // Can search
        public bool CanSearch
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Search);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Search;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Search;
                }
            }
        }

        // Can admin
        public bool CanAdmin
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Admin);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Admin;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Admin;
                }
            }
        }

        // Can import
        public bool CanImport
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Import);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Import;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Import;
                }
            }
        }

        // Can lookup
        public bool CanLookup
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Lookup);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Lookup;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Lookup;
                }
            }
        }

        // Can push
        public bool CanPush
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Push);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Push;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Push;
                }
            }
        }

        // Can export
        public bool CanExport
        {
            get => ((Allow)CurrentUserLevel).HasFlag(Allow.Export);
            set {
                if (value) {
                    CurrentUserLevel |= (int)Allow.Export;
                } else {
                    CurrentUserLevel &= ~(int)Allow.Export;
                }
            }
        }

        // Last URL
        public string LastUrl => Cookie["lasturl"];

        // Save last URL
        public void SaveLastUrl()
        {
            string s = CurrentUrl();
            if (LastUrl == s)
                s = "";
            if (!Regex.IsMatch(s, @"[?&]modal=1(&|$)")) // Query string does not contain "modal=1"
                Cookie["lasturl"] = s;
        }

        // Auto login
        public async Task<bool> AutoLoginAsync()
        {
            bool valid = false;
            var model = new LoginModel();
            <# if (isWindowsAuthenticate) { #>
            if (IsAuthenticated()) {
                model.Username = User?.Identity?.Name ?? "";
                model.Password = "";
                valid = await ValidateUser(model, true);
            }
            <# } #>
            if (!valid && SameString(Cookie["autologin"], "autologin")) {
                model.Username = Cookie["username"];
                model.Password = Cookie["password"];
                model.Username = Decrypt(model.Username);
                model.Password = Decrypt(model.Password);
                valid = await ValidateUser(model, true);
            }
            if (!valid && Config.AllowLoginByUrl && Get("username", out StringValues user) && !Empty(user)) {
                model.Username = RemoveXss(user);
                model.Password = RemoveXss(Get("password"));
                valid = await ValidateUser(model, true);
            }
        <# if (PROJ.SecLogInOutAuditTrail) { #>
            if (valid)
                await WriteAuditTrailAsync(model.Username, Language.Phrase("AuditTrailAutoLogin"), CurrentUserIpAddress());
        <# } #>
            return valid;
        }

        // Auto login
        public bool AutoLogin() => AutoLoginAsync().GetAwaiter().GetResult();

        // Login user
        public void LoginUser(string? userName = null, object? userID = null, object? parentUserID = null, string? userLevel = null, int allowedPermission = 0)
        {
            if (userName != null) {
                CurrentUserName = userName;
                if (userName == Language.Phrase("UserAdministrator")) // Handle language phrase as well
                    userName = Config.AdminUserName;
            }
            if (userID != null)
                SessionUserID = userID;
            if (parentUserID != null)
                SessionParentUserID = parentUserID;
            if (userLevel != null) {
                SessionUserLevelID = userLevel;
                int level = ConvertToInt(userLevel);
                if (level > -2) {
                    _isLoggedIn = true;
                    Session[Config.SessionStatus] = "login";
                    _isSysAdmin = level == -1;
                }
                SetupUserLevel();
            }
            // Set allowed permission
            SetAllowedPermissions(allowedPermission);
        }

        // Logout user
        public void LogoutUser()
        {
            _isLoggedIn = false;
            Session[Config.SessionStatus] = "";
            CurrentUserName = "";
            SessionUserID = "";
            SessionParentUserID = "";
            SessionUserLevelID = "-2";
            SetupUserLevel();
        }

        #pragma warning disable 162, 168, 219, 1998
        // Validate user
        public async Task<bool> ValidateUser(LoginModel model, bool autologin, string provider = "")
        {
            string usr = model.Username;
            string pwd = model.Password;
            string securitycode = model.SecurityCode ?? "";

            try {
                string filter, sql;
                bool valid = false, providerValid = false, saveUserProfile = false;

                // Login by external provider // DN
                if (!Empty(provider)) {
                    if (Config.Authentications.TryGetValue(provider, out AuthenticationProvider? p) && p != null && p.Enabled) {
                        Profile = ResolveProfile();
                        if (Profile.TryGetValue(ClaimTypes.Email.Split('/').Last(), out string? email) && email != null)
                            usr = email;
                        providerValid = true;
                    } else {
                        if (Config.Debug)
                            End("Provider for " + provider + " not found or not enabled.");
                        return false;
                    }
                }

                // Custom validate
                <# if (isWindowsAuthenticate) { #>
                bool customValid = IsAuthenticated(); // Windows user
                <# } else { #>
                bool customValid = false;
                <# } #>

            <# if (ServerScriptExist("Global", "User_CustomValidate")) { #>
                // Call User Custom Validate event
                if (Config.UseCustomLogin) {
                    customValid = UserCustomValidate(ref usr, ref pwd);
                    <# if (UseLdap()) { #>
                    if (!customValid) {
                        bool enabledLDAP = ConvertToBool(Configuration["LDAPSettings:Enabled"]);
                        if (enabledLDAP)
                        {
                            Ldap ??= new();
                            customValid = await Ldap.Bind(usr, pwd);
                        }
                    }
                    <# } #>
                }
            <# } #>

                // Handle provider login as custom login
                if (providerValid)
                    customValid = true;

                if (customValid) {
                    //Session[Config.SessionStatus] = "login"; // To be setup below
                    CurrentUserName = usr; // Load user name
                }

            <# if (isHardCodeAdmin) { #>
                if (!valid) {
                    string adminUserName = Config.AdminUserName;
                    string adminPassword = Config.AdminPassword;
                    if (Config.EncryptionEnabled) {
                        adminUserName = AesDecrypt(Config.AdminUserName);
                        adminPassword = AesDecrypt(Config.AdminPassword);
                    }
                    if (Config.CaseSensitivePassword) {
                        valid = (!customValid && adminUserName == usr && adminPassword == pwd) ||
                            (customValid && Config.AdminUserName == usr);
                    } else {
                        valid = (!customValid && SameText(adminUserName, usr)
                            && SameText(adminPassword, pwd)) ||
                            (customValid && SameText(adminUserName, usr));
                    }
                    if (valid) {
                        _isLoggedIn = true;
                        Session[Config.SessionStatus] = "login";
                        _isSysAdmin = true;
                        Session.SetInt(Config.SessionSysAdmin, 1); // System Administrator

                        CurrentUserName = Language.Phrase("UserAdministrator"); // Load user name
                    <# if (hasUserId) { #>
                        SessionUserID = -1; // System Administrator
                    <# } #>
                    <# if (isUserLevel) { #>
                        SessionUserLevelID = "-1"; // System Administrator
                        SetupUserLevel();
                    <# } #>
                    <# if (isCookieAuthenticate) { #>
                        // Sign in // DN
                        if (!IsAuthenticated() && HttpContext != null) {
                            Claims.Add(new ("UserName", usr));
                            Claims.Add(new ("UserLevelId", "-1"));
                            Claims.Add(new (ClaimTypes.Role, GetUserLevelName("-1"))); // "Administrator"
                            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                new ClaimsPrincipal(new ClaimsIdentity(Claims, CookieAuthenticationDefaults.AuthenticationScheme)));
                        }
                    <# } #>
                    <# if (checkPasswordExpiry) { #>
                        Profile[Config.UserProfileLastPasswordChangedDate] = DateTime.Today.ToString("yyyy'/'MM'/'dd");
                    <# } #>
                    }
                }
            <# } #>

            <# if (hasUserTable) { #>
                // Check other users
                if (!valid) {
                    if (Empty(usr)) // DN
                        return customValid;
                <#
                    let secLoginIdField = GetFieldObject(secTable, PROJ.SecLoginIDFld);
                    if (IsNumberType(secLoginIdField.FldType)) { // Numeric
                #>
                    if (!IsNumeric(usr))
                        return customValid;
                <#
                    }
                #>
                    filter = GetUserFilter(Config.LoginUsernameFieldName, usr);
                <#
                    if (PROJ.SecRegisterActivate && !IsEmpty(PROJ.SecRegisterActivateFld)) {
                #>
                    if (!Empty(Config.UserActivateFilter))
                        filter += " AND " + Config.UserActivateFilter;
                <#
                    }
                #>
                    // User table object (<#= secTblVar #>)
                    UserTable = Resolve("usertable")!;
                    UserTableConn ??= await GetConnectionAsync(UserTable.DbId);

                    // Set up filter (WHERE clause)
                    sql = UserTable.GetSql(filter); // DN

                    using var rsuser = await UserTableConn.GetDataReaderAsync(sql);
                    if (await rsuser.ReadAsync()) {
                        valid = customValid || ComparePassword(ConvertToString(GetUserInfo(Config.LoginPasswordFieldName, rsuser)), pwd);

                <# if (hasUserProfile) { #>
                        await Profile.LoadProfileFromDatabase(usr);
                <# } #>

            <# if (checkLoginRetry) { #>
                        // Set up retry count from manual login
                        int retrycount;
                        if (!autologin) {
                            if (!valid) {
                                retrycount = ConvertToInt(Profile.GetValue(Config.UserProfileLoginRetryCount));
                                retrycount++;
                                Profile[Config.UserProfileLoginRetryCount] = ConvertToString(retrycount);
                                Profile[Config.UserProfileLastBadLoginDateTime] = DateTime.Now.ToString("yyyy'/'MM'/'dd' 'HH':'mm':'ss");
                <# if (PROJ.SecLogInOutAuditTrail) { #>
                                await WriteAuditTrailAsync(usr, Language.Phrase("AuditTrailFailedAttempt").Replace("%n", ConvertToString(retrycount)), CurrentUserIpAddress());
                <# } #>
                            } else {
                                Profile[Config.UserProfileLoginRetryCount] = "0";
                            }
                            saveUserProfile = true;
                        }
            <# } #>

            <# if (checkConcurrentUser) { #>
                        // Check concurrent user login
                        if (valid && !await Profile.IsValidUser(usr, Session.SessionId, false)) {
                            return true; // Return true but do not login
                        }
            <# } #>

            <# if (checkPasswordExpiry) { #>
                        // Password Expiry checking
                        if (valid && !autologin) {
                            if (await Profile.PasswordExpired(usr, false)) {
                                SetSessionPasswordExpired();

                <# if (ServerScriptExist("Global", "User_PasswordExpired")) { #>
                                // Call user password expired event
                                <#= Await #>UserPasswordExpired(rsuser);
                <# } #>
                                if (IsPasswordExpired()) {
                <# if (PROJ.SecLogInOutAuditTrail) { #>
                                    await WriteAuditTrailAsync(usr, Language.Phrase("AuditTrailPasswordExpired"), CurrentUserIpAddress());
                <# } #>
                                    return false;
                                }
                            }
                        }
            <# } #>


                        if (valid) {

                            // Check two factor authentication
                            if (Config.UseTwoFactorAuthentication) {
                                // Check API login
                                if (IsApi()) {
                                    if (SameText(Config.TwoFactorAuthenticationType, "google") && (Config.ForceTwoFactorAuthentication || await Profile.HasUserSecret(usr, true))) // Verify security code
                                        if (!await Profile.Verify2FACode(usr, securitycode))
                                            return false;
                                } else if (Config.ForceTwoFactorAuthentication && !await Profile.HasUserSecret(usr, true)) { // Non API, go to 2fa page
                                    return valid;
                                }
                            }

                            _isLoggedIn = true;
                            Session[Config.SessionStatus] = "login";
                            _isSysAdmin = false;
                            Session.SetInt(Config.SessionSysAdmin, 0); // Non System Administrator
                            CurrentUserName = ConvertToString(GetUserInfo(Config.LoginUsernameFieldName, rsuser)); // Load user name
                            <# if (hasUserId) { #>
                            SessionUserID = GetUserInfo(Config.UserIdFieldName, rsuser) ?? ""; // Load user ID
                                <# if (!IsEmpty(DB.SecuParentUserIDFld)) { // Parent User ID #>
                            SessionParentUserID = GetUserInfo(Config.ParentUserIdFieldName, rsuser) ?? ""; // Load parent user ID
                                <# } #>
                            <# } #>
                            <# if (isUserLevel) { #>
                            SessionUserLevelID = ConvertToString(GetUserInfo(Config.UserLevelFieldName, rsuser)); // Load user level
                            SetupUserLevel();
                            <# } #>
                            Profile.Assign(GetDictionary(rsuser));
                            Profile.Remove(Config.LoginPasswordFieldName); // Delete password
                            // Set up User Image field in User Profile
                            if (!Empty(Config.UserImageFieldName)) {
                                DbField imageField = UserTable.Fields[Config.UserImageFieldName];
                                var mi = imageField.GetType().GetMethod("GetUploadPath");
                                if (mi != null) // GetUploadPath
                                    imageField.UploadPath = ConvertToString(mi.Invoke(imageField, null));
                                byte[]? image = await GetFileImage(imageField, GetUserInfo(Config.UserImageFieldName, rsuser), Config.UserImageSize, Config.UserImageSize, Config.UserImageCrop);
                                if (image != null)
                                    Profile.SetValue(Config.UserProfileImage, Convert.ToBase64String(image)); // Save as base64 encoded
                                saveUserProfile = true;
                            }
                            <# if (ServerScriptExist("Global", "User_Validated")) { #>
                            // User Validated event
                            valid = <#= Await #>UserValidated(rsuser);
                            <# } #>
                            <# if (isCookieAuthenticate) { #>
                            if (valid) { // Sign in // DN
                                if (!IsAuthenticated() && HttpContext != null) {
                                    Claims.Add(new ("UserName", usr));
                                    // Claims.Add(new (ClaimTypes.Role, GetUserLevelName(SessionUserLevelID)));
                                    <# if (hasUserId) { #>
                                    Claims.Add(new ("Id", ConvertToString(SessionUserID))); // User ID
                                        <# if (!IsEmpty(DB.SecuParentUserIDFld)) { // Parent User ID #>
                                    Claims.Add(new ("ParentUserId", ConvertToString(SessionParentUserID))); // Parent user ID
                                        <# } #>
                                    <# } #>
                                    <# if (isUserLevel) { #>
                                    Claims.Add(new ("UserLevelId", SessionUserLevelID));
                                    <# } #>
                                    // Set up User Email field
                                    if (!Empty(Config.UserEmailFieldName))
                                        Claims.Add(new (ClaimTypes.Email, ConvertToString(GetUserInfo(Config.UserEmailFieldName, rsuser))));
                                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                        new ClaimsPrincipal(new ClaimsIdentity(Claims, CookieAuthenticationDefaults.AuthenticationScheme)));

                                }
                            }
                            <# } #>
                        }
                    <# if (hasUserProfile) { #>
                        if (saveUserProfile) {
                            rsuser.Dispose(); // Dispose data reader
                            await Profile.SaveProfileToDatabase(usr); // Save profile
                        }
                    <# } #>
                    } else { // User not found in user table
                        if (customValid) { // Grant default permissions
                            CurrentUserName = usr;
                            <# if (hasUserId) { #>
                            SessionUserID = usr; // User name as User ID
                            <# } #>
                            <# if (isUserLevel) { #>
                            SessionUserLevelID = "-2"; // Anonymous User Level
                            SetupUserLevel();
                            <# } #>
                            <# if (ServerScriptExist("Global", "User_Validated")) { #>
                            // User Validated event
                            customValid = <#= Await #>UserValidated(null);
                            <# } #>
                            <# if (isCookieAuthenticate) { #>
                            if (customValid) { // Sign in // DN
                                if (!IsAuthenticated() && HttpContext != null) {
                                    Claims.Add(new ("Name", usr));
                                    Claims.Add(new ("UserName", usr));
                                    Claims.Add(new ("UserLevelId", "-2"));
                                    Claims.Add(new (ClaimTypes.Role, GetUserLevelName("-2"))); // "Anonymous"
                                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                                        new ClaimsPrincipal(new ClaimsIdentity(Claims, CookieAuthenticationDefaults.AuthenticationScheme)));
                                }
                            }
                            <# } #>
                        }
                    }
                }

            <# } else { // No user table #>
                <# if (ServerScriptExist("Global", "User_Validated")) { #>
                // User Validated event
                if (customValid)
                    customValid = <#= Await #>UserValidated(null);
                <# } #>
            <# } #>

                Profile.Save();

                if (customValid)
                    return customValid;

                if (!valid && !IsPasswordExpired()) {
                    _isLoggedIn = false;
                    Session[Config.SessionStatus] = ""; // Clear login status
                }

                return valid;

            } finally {
                model.Username = usr;
                model.Password = pwd;
            }
        }
        #pragma warning restore 162, 168, 219, 1998

        <# if (isStaticUserLevel) { #>

        // Static User Level security
        public void SetupUserLevel()
        {

            // Load user level from user level settings
            UserLevel = Config.UserLevels;
            UserLevelPriv = Config.UserLevelPermissions;

        <# if (ServerScriptExist("Global", "UserLevel_Loaded")) { #>
            // User Level loaded event
            UserLevelLoaded();
        <# } #>

            // Save the User Level to Session variable
            SaveUserLevel();
        }

        <# } else if (isDynamicUserLevel) { #>

        // Dynamic User Level security

        // Get User Level settings from database
        public void SetupUserLevel()
        {

            SetupUserLevels().GetAwaiter().GetResult(); // Load all user levels
    <# if (ServerScriptExist("Global", "UserLevel_Loaded")) { #>
            // User Level loaded event
            UserLevelLoaded();
    <# } #>

            // Check permissions
            CheckPermissions();

            // Save the User Level to Session variable
            SaveUserLevel();
        }

        // Check Anonymous user level
        private bool _anoymousUserLevelChecked = false;

        // Get all User Level settings from database
        public async Task<bool> SetupUserLevels()
        {

            // Load user level from user level settings first
            var userLevel = Config.UserLevels;
            var userLevelPriv = Config.UserLevelPermissions;
            var tables = Config.UserLevelTablePermissions;

            // User level table connection
            var tbl = (IQueryFactory)Resolve(Config.UserLevelTableName)!;

            // User level permission table connection
            var privTbl = (IQueryFactory)Resolve(Config.UserLevelPrivTableName)!;

            // Add Anonymous user level
            if (Config.CheckOldUserLevels && !_anoymousUserLevelChecked) {
                if (!(await tbl.GetQueryBuilder().Where(Config.UserLevelIdFieldName, -2).ExistsAsync()))
                    await tbl.GetQueryBuilder().InsertAsync(new UserLevel { Id = -2, Name = Language.Phrase("UserAnonymous") });
            }

            // Get the User Levels
            UserLevel = (await tbl.GetQueryBuilder().Select($"{Config.UserLevelIdField} as Id", $"{Config.UserLevelNameField} as Name").GetAsync<UserLevel>()).ToList();

            // Add Anonymous user privileges
            if (Config.CheckOldUserLevels && !_anoymousUserLevelChecked) {
                if (!(await privTbl.GetQueryBuilder().Where(Config.UserLevelPrivUserLevelIdFieldName, -2).ExistsAsync())) {
                    var wrkUserLevel = Config.UserLevels;
                    var wrkUserLevelPriv = Config.UserLevelPermissions;
                    var columns = new [] { Config.UserLevelPrivUserLevelIdFieldName, Config.UserLevelPrivTableNameFieldName, Config.UserLevelPrivPrivFieldName };
                    var valuesCollection = Config.UserLevelTablePermissions.Select(item => new object[] {
                        -2,
                        item.ProjectId + item.TableName,
                        ConvertToInt(wrkUserLevelPriv.FirstOrDefault(userpriv => SameString(userpriv.Table, item.ProjectId + item.TableName) && SameString(userpriv.Id, "-2"))?.Permission)
                    });
                    await privTbl.GetQueryBuilder().InsertAsync(columns, valuesCollection);
                }
                _anoymousUserLevelChecked = true;
            }

            // Get the User Level privileges
            QueryBuilder qb1 = privTbl.GetQueryBuilder()
                .Select($"{Config.UserLevelPrivTableNameField} as Table", $"{Config.UserLevelPrivUserLevelIdField} as Id", $"{Config.UserLevelPrivPrivField} as Permission");
            if (!IsApi() && !IsAdmin && UserLevelID.Count > 0) {
                qb1.WhereIn(Config.UserLevelPrivUserLevelIdFieldName, UserLevelID);
                Session[Config.SessionUserLevelListLoaded] = UserLevelList(); // Save last loaded list
            } else {
                Session[Config.SessionUserLevelListLoaded] = ""; // Save last loaded list
            }
            UserLevelPriv = (await qb1.GetAsync<UserLevelPermission>()).ToList();

            // Update User Level privileges record if necessary
            if (Config.CheckOldUserLevels) {
                string projectID = CurrentProjectID,
                    relatedProjectID = Config.RelatedProjectId;
                int reloadUserPriv = 0;

                // Update table with report prefix
                if (!Empty(relatedProjectID)) {
                    QueryBuilder qb2 = privTbl.GetQueryBuilder();
                    qb2.WhereExists(q =>
                        q.From(Config.UserLevelPrivTable).WhereStarts(Config.UserLevelPrivTableNameFieldName, relatedProjectID, true)
                    );
                    if (await qb2.ExistsAsync()) {
                        QueryBuilder qb3 = privTbl.GetQueryBuilder();
                        var ar = tables.Select(t => relatedProjectID + t.TableName);
                        var c = await GetConnectionAsync(Config.UserLevelPrivDbId);
                        reloadUserPriv += await qb3.WhereIn(Config.UserLevelPrivTableNameField, ar).UpdateAsync(new Dictionary<string, object> {
                            {
                                Config.UserLevelPrivTableNameFieldName,
                                new SqlKata.UnsafeLiteral(c.Concat("'" + AdjustSql(projectID, Config.UserLevelPrivDbId) + "'", QuotedName(Config.UserLevelPrivTableNameField, Config.UserLevelPrivDbId)))
                            }
                        });
                    }
                }

                // Reload the User Level privileges
                if (reloadUserPriv > 0)
                    UserLevelPriv = (await privTbl.GetQueryBuilder().GetAsync<UserLevelPermission>()).ToList();
            }

            // Warn user if user level not setup
            if (UserLevelPriv.Count == 0 && IsAdmin && Empty(Session[Config.SessionUserLevelMessage])) {
                CurrentPage?.SetFailureMessage(Language.Phrase("NoUserLevel"));
                Session[Config.SessionUserLevelMessage] = "1"; // Show only once
                return false; // To be redirected in userpriv // DN
            }

            return true;
        }

        // Update user level permissions (using main connection)
        public async Task<bool> UpdatePermissions(int userLevel, Dictionary<string, int> privileges)
        {
            var tbl = (IQueryFactory)Resolve(Config.UserLevelPrivTableName)!;
            foreach (var (key, value) in privileges) {
                var where = new Dictionary<string, object> {
                        { Config.UserLevelPrivTableNameFieldName, key },
                        { Config.UserLevelPrivUserLevelIdFieldName, userLevel }
                    };
                if (await tbl.GetQueryBuilder(true).Where(where).ExistsAsync())
                    await tbl.GetQueryBuilder(true).Where(where).UpdateAsync(new Dictionary<string, object> { { Config.UserLevelPrivPrivFieldName, value } });
                else
                    await tbl.GetQueryBuilder(true).InsertAsync(new UserLevelPermission { Table = key, Id = userLevel, Permission = value });
            }
            return true;
        }

        <# } else if (isSecurityEnabled) { #>

        // User Level security (Anonymous)
        public void SetupUserLevel()
        {
            UserLevel = Config.UserLevels;
            UserLevelPriv = Config.UserLevelPermissions;

            // Check permissions
            CheckPermissions();

            // Save the User Level to Session variable
            SaveUserLevel();
        }

        <# } else { #>

        // No user level security
        public void SetupUserLevel()
        {
        }

        <# } #>

        // Check import/lookup permissions
        protected void CheckPermissions()
        {
        <# if (PROJ.FallBackUserLevelPermissions) { #>
            if (IsList(UserLevelPriv)) {
                for (int i = 0; i < UserLevelPriv.Count; i++) {
                    var row = UserLevelPriv[i];
                    var permission = (Allow)row.Permission;
                    if (!permission.HasFlag(Allow.Import) && IsAdmin)
                        row.Permission |= (int)Allow.Import; // Import permission not setup, use Admin
                    if (!permission.HasFlag(Allow.Export) && permission.HasFlag(Allow.List))
                        row.Permission |= (int)Allow.Export; // Export permission not setup, use List
                    if (!permission.HasFlag(Allow.Lookup) && permission.HasFlag(Allow.List))
                        row.Permission |= (int)Allow.Lookup; // Lookup permission not setup, use List
                    if (!permission.HasFlag(Allow.Push) && IsAdmin)
                        row.Permission |= (int)Allow.Push; // Push permission not setup, use Admin
                }
            }
        <# } #>
        }

        // Set allowed permissions
        protected void SetAllowedPermissions(int permission = 0)
        {
            if (permission > 0) {
                if (IsList(UserLevelPriv)) {
                    for (int i = 0; i < UserLevelPriv.Count; i++) {
                        var row = UserLevelPriv[i];
                        row.Permission &= permission;
                    }
                }
            }
        }

        // Add user permission
        public void AddUserPermission(string userLevelName, string tableName, int permission)
        {
            string UserLevelID = "";
            // Get user level ID from user name
            if (IsList(UserLevel))
                UserLevelID = ConvertToString(UserLevel.FirstOrDefault(row => SameString(userLevelName, row.Name))?.Id);
            if (IsList(UserLevelPriv) && !Empty(UserLevelID)) {
                var row = UserLevelPriv.FirstOrDefault(r => SameString(r.Table, Config.ProjectId + tableName) && SameString(r.Id, UserLevelID));
                if (row != null)
                    row.Permission |= permission; // Add permission
                else
                    UserLevelPriv.Add(new UserLevelPermission { Id = ConvertToInt(UserLevelID), Table = Config.ProjectId + tableName, Permission = permission });
            }
        }

        // Add user permission
        public void AddUserPermission(string userLevelName, string tableName, Allow permission) =>
            AddUserPermission(userLevelName, tableName, (int)permission);

        // Add user permission
        public void AddUserPermission(List<string> userLevelName, List<string> tableName, int permission) =>
            userLevelName.ForEach(_userLevelName => tableName.ForEach(_tableName => AddUserPermission(_userLevelName, _tableName, permission)));

        // Add user permission
        public void AddUserPermission(List<string> userLevelName, List<string> tableName, Allow permission) =>
            AddUserPermission(userLevelName, tableName, (int)permission);

        // Add user permission
        public void AddUserPermission(string userLevelName, List<string> tableName, int permission) =>
            tableName.ForEach(name => AddUserPermission(userLevelName, name, permission));

        // Add user permission
        public void AddUserPermission(string userLevelName, List<string> tableName, Allow permission) =>
            AddUserPermission(userLevelName, tableName, (int)permission);

        // Add user permission
        public void AddUserPermission(List<string> userLevelName, string tableName, int permission) =>
            userLevelName.ForEach(name => AddUserPermission(name, tableName, permission));

        // Add user permission
        public void AddUserPermission(List<string> userLevelName, string tableName, Allow permission) =>
            AddUserPermission(userLevelName, tableName, (int)permission);

        // Delete user permission
        public void DeleteUserPermission(string userLevelName, string tableName, int permission)
        {
            string UserLevelID = "";
            // Get user level ID from user name
            if (IsList(UserLevel))
                UserLevelID = ConvertToString(UserLevel.FirstOrDefault(row => SameString(userLevelName, row.Name))?.Id);
            if (IsList(UserLevelPriv) && !Empty(UserLevelID)) {
                var row = UserLevelPriv.FirstOrDefault(r => SameString(r.Table, Config.ProjectId + tableName) && SameString(r.Id, UserLevelID));
                if (row != null)
                    row.Permission &= ~permission; // Remove permission
            }
        }

        // Delete user permission
        public void DeleteUserPermission(string userLevelName, string tableName, Allow permission) =>
            DeleteUserPermission(userLevelName, tableName, (int)permission);

        // Delete user permission
        public void DeleteUserPermission(List<string> userLevelName, List<string> tableName, int permission) =>
            userLevelName.ForEach(_userLevelName => tableName.ForEach(_tableName => DeleteUserPermission(_userLevelName, _tableName, permission)));

        // Delete user permission
        public void DeleteUserPermission(List<string> userLevelName, List<string> tableName, Allow permission) =>
            DeleteUserPermission(userLevelName, tableName, (int)permission);

        // Delete user permission
        public void DeleteUserPermission(string userLevelName, List<string> tableName, int permission) =>
            tableName.ForEach(name => DeleteUserPermission(userLevelName, name, permission));

        // Delete user permission
        public void DeleteUserPermission(string userLevelName, List<string> tableName, Allow permission) =>
            DeleteUserPermission(userLevelName, tableName, (int)permission);

        // Delete user permission
        public void DeleteUserPermission(List<string> userLevelName, string tableName, int permission) =>
            userLevelName.ForEach(name => DeleteUserPermission(name, tableName, permission));

        // Delete user permission
        public void DeleteUserPermission(List<string> userLevelName, string tableName, Allow permission) =>
            DeleteUserPermission(userLevelName, tableName, (int)permission);

        // Load table permissions
        public void LoadTablePermissions(string tblVar)
        {
            string tblName = GetTableName(tblVar);
            if (IsLoggedIn)
                Invoke(this, "TablePermissionLoading");
            LoadCurrentUserLevel(Config.ProjectId + tblName);
            if (IsLoggedIn) {
                Invoke(this, "TablePermissionLoaded");
            }
            if (IsLoggedIn) {
                Invoke(this, "UserIdLoading");
                Invoke(this, "LoadUserID");
                Invoke(this, "UserIdLoaded");
            }
        }

        // Load current user level
        public void LoadCurrentUserLevel(string table)
        {
            // Load again if user level list changed
            if (!Empty(Session[Config.SessionUserLevelListLoaded]) &&
                !SameString(Session[Config.SessionUserLevelListLoaded], Session[Config.SessionUserLevelList])) { // Compare strings, not objects // DN
                Session[Config.SessionUserLevelPrivArrays] = null;
            }
            LoadUserLevel();
            SessionUserLevel = CurrentUserLevelPriv(table);
        }

        // Get current user privilege
        protected int CurrentUserLevelPriv(string tableName)
        {
            if (IsLoggedIn) {
        <# if (isUserLevel) { #>
                return UserLevelID.Aggregate(0, (result, id) => result | GetUserLevelPriv(tableName, id));
        <# } else { // DN #>
                return (int)Allow.All;
        <# } #>
            } else { // Anonymous
                return GetUserLevelPriv(tableName, -2);
            }
        }

        // Get user level ID by user level name
        public int GetUserLevelID(string userLevelName)
        {
            if (SameString(userLevelName, "Anonymous")) {
                return -2;
            } else if (SameString(userLevelName, Language?.Phrase("UserAnonymous"))) {
                return -2;
            } else if (SameString(userLevelName, "Administrator")) {
                return -1;
            } else if (SameString(userLevelName, Language?.Phrase("UserAdministrator"))) {
                return -1;
            } else if (SameString(userLevelName, "Default")) {
                return 0;
            } else if (SameString(userLevelName, Language?.Phrase("UserDefault"))) {
                return 0;
            } else if (!Empty(userLevelName)) {
                if (IsList(UserLevel)) {
                    var row = UserLevel.FirstOrDefault(r => SameString(r.Name, userLevelName));
                    if (row != null)
                        return row.Id;
                }
            }
            return -2; // Anonymous
        }

        // Add Add User Level by name
        public void AddUserLevel(string userLevelName)
        {
            if (Empty(userLevelName))
                return;
            int id = GetUserLevelID(userLevelName);
            AddUserLevelID(id);
        }

        // Add User Level by ID
        public void AddUserLevelID(int id)
        {
            if (!IsNumeric(id) || id < -1)
                return;
            if (!UserLevelID.Contains(id)) {
                UserLevelID.Add(id);
                Session[Config.SessionUserLevelList] = UserLevelList(); // Update session variable
            }
        }

        // Delete User Level by name
        public void DeleteUserLevel(string userLevelName)
        {
            if (Empty(userLevelName))
                return;
            int id = GetUserLevelID(userLevelName);
            DeleteUserLevelID(id);
        }

        // Delete User Level by ID
        public void DeleteUserLevelID(int id)
        {
            if (!IsNumeric(id) || id < -1)
                return;

            if (UserLevelID.Contains(id)) {
                UserLevelID.Remove(id);
                Session[Config.SessionUserLevelList] = UserLevelList(); // Update session variable
            }
        }

        // User level list
        public string UserLevelList() => String.Join(", ", UserLevelID);

        // User level list
        public bool UserLevelIDExists(int id) => IsList(UserLevel) && UserLevel.Exists(row => row.Id == id);

        // User level name list
        public string UserLevelNameList()
        {
            string list = "";
            <# if (isDynamicUserLevel) { #>
            list = String.Join(", ", UserLevelID.Select(id => QuotedValue(GetUserLevelName(ConvertToString(id)), DataType.String, Config.UserLevelDbId)));
            <# } #>
            return list;
        }

        // Get user privilege based on table name and user level
        public int GetUserLevelPriv(string tableName, int userLevelId)
        {
            if (userLevelId == -1) { // System Administrator
                return (int)Allow.All;
            } else if (userLevelId >= 0 || userLevelId == -2) {
                if (IsList(UserLevelPriv))
                    return UserLevelPriv.FirstOrDefault(row => SameString(row.Table, tableName) && row.Id == userLevelId)?.Permission ?? 0;
            }
            return 0;
        }

        // Get current user level name
        public string CurrentUserLevelName => GetUserLevelName(CurrentUserLevelID);

        // Get user level name based on user level
        public string GetUserLevelName(string? userLevelId, bool lang = true)
        {
            List<int> ids = userLevelId?.Split(Config.MultipleOptionSeparator)
                .Where(x => int.TryParse(x, out _))
                .Select(int.Parse)
                .Where(x => x >= -2).ToList() ?? new ();
            var names = ids.Select(id => {
                if (id == -2) {
                    return lang ? Language.Phrase("UserAnonymous") : "Anonymous";
                } else if (id == -1) {
                    return lang ? Language.Phrase("UserAdministrator") : "Administrator";
                } else if (id == 0) {
                    return lang ? Language.Phrase("UserDefault") : "Default";
                } else {
                    if (IsList(UserLevel)) {
                        string name = UserLevel.FirstOrDefault(row => row.Id == id)?.Name ?? "";
                        string userLevelName = lang ? Language.Phrase(name) : "";
                        return (userLevelName != "") ? userLevelName : name;
                    }
                    return id.ToString();
                }
            });
            return String.Join(", ", names);
        }

        // Display all the User Level settings (for debug only)
        public void ShowUserLevelInfo()
        {
            if (IsList(UserLevel)) {
                Write("User Levels:<br>");
                VarDump(UserLevel);
            } else {
                Write("No User Level definitions." + "<br>");
            }
            if (IsList(UserLevelPriv)) {
                Write("User Level Privs:<br>");
                VarDump(UserLevelPriv);
            } else {
                Write("No User Level privilege settings." + "<br>");
            }
            Write("CurrentUserLevel = " + CurrentUserLevel + "<br>");
            Write("User Levels = " + UserLevelList() + "<br>");
        }

        // Check privilege for List page (for menu items)
        public bool AllowList(string tableName) => ConvertToBool((Allow)CurrentUserLevelPriv(tableName) & Allow.List);

        // Check privilege for View page (for Allow-View / Detail-View)
        public bool AllowView(string tableName) => ConvertToBool((Allow)CurrentUserLevelPriv(tableName) & Allow.View);

        // Check privilege for Add page (for Allow-Add / Detail-Add)
        public bool AllowAdd(string tableName) => ConvertToBool((Allow)CurrentUserLevelPriv(tableName) & Allow.Add);

        // Check privilege for Edit page (for Detail-Edit)
        public bool AllowEdit(string tableName) => ConvertToBool((Allow)CurrentUserLevelPriv(tableName) & Allow.Edit);

        // Check privilege for Delete page (for API)
        public bool AllowDelete(string tableName) => ConvertToBool((Allow)CurrentUserLevelPriv(tableName) & Allow.Delete);

        // Check privilege for lookup
        public bool AllowLookup(string tableName) => ConvertToBool((Allow)CurrentUserLevelPriv(tableName) & Allow.Lookup);

        // Check privilege for export
        public bool AllowExport(string tableName) => ConvertToBool((Allow)CurrentUserLevelPriv(tableName) & Allow.Export);

        // Check if user password expired
        public bool IsPasswordExpired => SameString(Session[Config.SessionStatus], "passwordexpired");

        // Set session password expired
        public void SetSessionPasswordExpired() => Session[Config.SessionStatus] = "passwordexpired";

        // Check if user password reset
        public bool IsPasswordReset => SameString(Session[Config.SessionStatus], "passwordreset");

        // Check if user is logging in (after changing password)
        public bool IsLoggingIn => SameString(Session[Config.SessionStatus], "loggingin");

        // Check if user is logging in (2FA)
        public bool IsLoggingIn2FA => SameString(Session[Config.SessionStatus], "loggingin2fa");

        // Check if user is logged in
        public bool IsLoggedIn => UseSession ? SameString(Session[Config.SessionStatus], "login") : _isLoggedIn;

        // Check if user is system administrator
        public bool IsSysAdmin => UseSession ? (Session.GetInt(Config.SessionSysAdmin) == 1) : _isSysAdmin;

        // Check if user is administrator
        public bool IsAdmin
        {
            get {
                bool res = IsSysAdmin;
                <# if (isUserLevel) { #>
                if (!res)
                    res = SameString(CurrentUserLevelID, "-1") || UserLevelID.Contains(-1) || CanAdmin;
                <# } #>
                <# if (hasUserId) { #>
                if (!res)
                    res = SameString(CurrentUserID, "-1") || UserID.Contains("-1");
                <# } #>
                return res;
            }
        }

        // Save user level to session
        public void SaveUserLevel()
        {
            Session.SetValue(Config.SessionUserLevelArrays, UserLevel); // DN
            Session.SetValue(Config.SessionUserLevelPrivArrays, UserLevelPriv); // DN
        }

        // Load user level from session // DN
        public void LoadUserLevel()
        {
            if (Session[Config.SessionUserLevelArrays] == null ||
                Session[Config.SessionUserLevelPrivArrays] == null ||
                Empty(Session[Config.SessionUserLevelArrays]) ||
                Empty(Session[Config.SessionUserLevelPrivArrays]) ||
                IsEmptyList(Session[Config.SessionUserLevelArrays]) ||
                IsEmptyList(Session[Config.SessionUserLevelPrivArrays])) { // DN
                SetupUserLevel();
            } else {
                UserLevel = Session.GetValue<List<UserLevel>>(Config.SessionUserLevelArrays)!;
                UserLevelPriv = Session.GetValue<List<UserLevelPermission>>(Config.SessionUserLevelPrivArrays)!;
            }
        }

    <#
        if (hasUserId) {
            // User ID field
            FIELD = GetFieldObject(secTable, DB.SecuUserIDFld);
            let secUserIdFldDataType = GetFieldTypeName(FIELD.FldType),
                secUserIdFldIsNumeric = IsNumberType(FIELD.FldType);
    #>

        // Get user email
        public string CurrentUserEmail
        {
            get {
                var email = User?.FindFirst(ClaimTypes.Email)?.Value;
                if (Empty(email) && !Empty(Config.UserEmailFieldName))
                    email = ConvertToString(CurrentUserInfo(Config.UserEmailFieldName));
                return email ?? "";
            }
        }

        // Get user ID value by user login name
        public object GetUserIDByUserName(string userName)
        {
            object userId = "";
            if (!Empty(userName)) {
                string filter = GetUserFilter(Config.LoginUsernameFieldName, userName);
                string sql = UserTable.GetSql(filter); // DN
                var conn = GetConnection(Config.UserTableDbId);
                var row = conn.GetRow(sql);
                row?.TryGetValue(Config.UserIdFieldName, out userId);
                return userId;
            }
            return userId;
        }

        // Load user ID
        public void LoadUserID()
        {
            if (Empty(CurrentUserID)) {
                // Handle empty User ID here
            } else if (!SameString(CurrentUserID, "-1")) { // Get first level
                AddUserID(CurrentUserID);
                UserTable = Resolve("usertable")!;
                string filter = ConvertToString(UserTable.Invoke("GetUserIDFilter", new object[] { CurrentUserID }));
                string sql = UserTable.GetSql(filter);
                var conn = GetConnection(Config.UserTableDbId);
                var rows = conn.GetRows(sql); // Always use Sync
                foreach (var row in rows)
                    AddUserID(GetUserInfo(Config.UserIdFieldName, row));
    <#
            if (hasParentUserId) {
                let parentUserIdField = GetFieldObject(secTable, DB.SecuParentUserIDFld),
                    parentUserIdFld = FieldSqlName(parentUserIdField, GetDbId(secTable.TblName));
    #>
                // Recurse all levels (hierarchical user id)
                string userIdList, currentUserIdList;
                currentUserIdList = UserIDList();
                userIdList = "";
                while (userIdList != currentUserIdList) {
        <# if (IsNumberType(parentUserIdField.FldType)) { #>
                    filter = "<#= Quote(parentUserIdFld) #> IN (" + currentUserIdList + ")";
        <# } else { #>
                    filter = MultiValueFilter("<#= Quote(parentUserIdFld) #>", UserID, Config.UserTableDbId);
        <# } #>
                    sql = UserTable.GetSql(filter);
                    var rows2 = conn.GetRows(sql); // Always use Sync
                    foreach (var row2 in rows2)
                        AddUserID(GetUserInfo(Config.UserIdFieldName, row2));
                    userIdList = currentUserIdList;
                    currentUserIdList = UserIDList();
                }
    <#
            }
    #>
            }
        }

        // Add user name
        public void AddUserName(string userName) => AddUserID(GetUserIDByUserName(userName));

        // Add user name
        public void AddUserIDByUserName(string userName) => AddUserName(userName);

        // Add user ID
        public void AddUserID(object id)
        {
            if (Empty(id))
                return;
    <# if (secUserIdFldIsNumeric) { #>
            if (!IsNumeric(id))
                return;
    <# } #>
            string userId = ConvertToString(id);
            if (!UserID.Contains(userId))
                UserID.Add(userId);
        }

        // Delete user name
        public void DeleteUserName(string userName) => DeleteUserID(GetUserIDByUserName(userName));

        // Delete user name
        public void DeleteUserIDByUserName(string userName) => DeleteUserName(userName);

        // Delete user ID
        public void DeleteUserID(object id)
        {
            if (Empty(id))
                return;
    <# if (secUserIdFldIsNumeric) { #>
            if (!IsNumeric(id))
                return;
    <# } #>
            UserID.Remove(ConvertToString(id));
        }

        // User ID list
        public string UserIDList() =>
            String.Join(", ", UserID.Select(id => QuotedValue(id, <#= secUserIdFldDataType #>, Config.UserTableDbId)));

    <# if (hasParentUserId) { #>

        // Add parent user ID
        public void AddParentUserID(object id)
        {
            if (Empty(id))
                return;
    <# if (secUserIdFldIsNumeric) { #>
            if (!IsNumeric(id))
                return;
    <# } #>
            string userId = ConvertToString(id);
            if (!ParentUserID.Contains(userId))
                ParentUserID.Add(userId);
        }

        // Delete parent user ID
        public void DeleteParentUserID(object id)
        {
            if (Empty(id))
                return;
    <# if (secUserIdFldIsNumeric) { #>
            if (!IsNumeric(id))
                return;
    <# } #>
            ParentUserID.Remove(ConvertToString(id));
        }

        // Parent user ID list
        public string ParentUserIDList(object? userid)
        {
            if (SameString(userid, CurrentUserID)) // Own record
                return String.Join(", ", ParentUserID.Select(id => QuotedValue(id, <#= secUserIdFldDataType #>, Config.UserTableDbId)));
            else
                return String.Join(", ", UserID.Where(id => !SameString(id, userid)).Select(id => QuotedValue(id, <#= secUserIdFldDataType #>, Config.UserTableDbId)));
        }

    <# } #>

        // Is valid user ID
        public bool IsValidUserID(object? id) => IsLoggedIn && (UserID.Contains(ConvertToString(id)) || SameString(id, CurrentUserID));

    <#
        } else { // !hasUserId // DN
    #>
        public bool IsValidUserID(object? id) => true;
    <#
        }
    #>

        <# if (hasUserId || hasUserTable) { // DN #>
        // Get user info
        public async Task<object?> CurrentUserInfoAsync(string fldname)
        {
            object? info = null;
            if (!Empty(Config.UserTable) && !IsSysAdmin) {
                try {
                <# if (hasUserId) { #>
                    string filter = GetUserFilter(Config.UserIdFieldName, CurrentUserID);
                <# } else { #>
                    string filter = GetUserFilter(Config.LoginUsernameFieldName, CurrentUserName);
                <# } #>
                    if (!Empty(filter)) {
                        string sql = UserTable.GetSql(filter);
                        var row = await ExecuteRowAsync(sql, Config.UserTableDbId);
                        info = GetUserInfo(fldname, row);
                    }
                    if (info == null && IsAuthenticated())
                        info = User?.FindFirst(fldname)?.Value;
                } catch {
                    if (Config.Debug)
                        throw;
                }
            }
            return info;
        }

        // Get user info
        public object? CurrentUserInfo(string fldname) => CurrentUserInfoAsync(fldname).GetAwaiter().GetResult();
        <# } #>

        <#= GetVirtualEvent("Global", "UserID_Loading") #>
        <#= GetVirtualEvent("Global", "UserID_Loaded") #>
        <#= GetVirtualEvent("Global", "UserLevel_Loaded") #>
        <#= GetVirtualEvent("Global", "TablePermission_Loading") #>
        <#= GetVirtualEvent("Global", "TablePermission_Loaded") #>
        <#= GetVirtualEvent("Global", "User_CustomValidate") #>
        <#= GetVirtualEvent("Global", "User_Validated") #>
        <#= GetVirtualEvent("Global", "User_PasswordExpired") #>

    }

<## Model class end #>
<#= include('shared/model-class-end.cs') #>