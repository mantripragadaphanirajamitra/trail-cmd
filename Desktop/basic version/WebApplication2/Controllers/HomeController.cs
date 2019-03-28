using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Security;
using System.Web.Mvc;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using WebApplication2.Models;
using System.Net.Mail;
using log4net;
using log4net.Config;
using System.IO;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;
using System.Net;
using System.Web;
using System.Threading;
using System.Security.Permissions;

namespace WebApplication2.Controllers
{
    public class HomeController : Controller
    {
         private static log4net.ILog Log { get; set;  }
        private static int cssrecords;
        private static int successrcrd;
        private static int failedrcrd;
        private static bool threadstop;
        Thread thread = new Thread(WorkThreadFunction);


        ILog log = log4net.LogManager.GetLogger(typeof(HomeController)); 
        // GET: Home
        public ActionResult Index()
        {
            log.Debug("DebugMessage");
            log.Warn("WarnMessage");
            log.Error("ErrorMessage");
            log.Fatal("FatalMessage");

            return View();
        }

        [SecurityPermissionAttribute(SecurityAction.Demand, ControlThread = true)]
        public JsonResult bulkusers1()
        {

            threadstop = true;
            cssrecords = -1;
           
            
            return Json("success", JsonRequestBehavior.AllowGet);
        }

        public ActionResult authforpswdreset1()
        {
            paresetEntities dc = new paresetEntities();
            List<Userinfo> lstResult = (from table in dc.Userinfoes
                                      where table.username == User.Identity.Name
                                      select table).ToList();
            userinffrpwdrst obj = new userinffrpwdrst();
            obj.username = lstResult[0].username.ToString();
            obj.email = lstResult[0].email.ToString();
            obj.phone = lstResult[0].phone.ToString();

            return View(obj);
        }
        public static List<string> loadCsvFile(string filePath)
        {
            var reader = new StreamReader(System.IO.File.OpenRead(filePath));
            List<string> searchList = new List<string>();
            while (!reader.EndOfStream)
            {
                var line = reader.ReadLine();
                searchList.Add(line);
            }
            return searchList;
        }
        public ActionResult progressbar()
        {
            return View();
        }
        public ActionResult bulkUsers()
        {
            return View();
        }

        public static void WorkThreadFunction( object importcsv)
        {
             paresetEntities dc = new paresetEntities();
            List<string> csvvalue1 = loadCsvFile(importcsv.ToString());
            string[] _values = null;
            failedrcrd = 0;
            threadstop = false;
            foreach (string obj in csvvalue1)
            {
                if (threadstop == true)
                {
                    break;
                }
                _values = obj.Split(',');
               
                    // var user = dc.Userinfoes.FirstOrDefault(m => m.username == _values[0].ToString());
                    string name = _values[0].ToString();
                    List<string> lstResult = (from table in dc.Userinfoes
                                              where table.username == name
                                              select table.password).ToList();
                    if (lstResult.Count == 0)
                    {
                        Userinfo u = new Userinfo();
                        var crypto = new SimpleCrypto.PBKDF2();
                        var encrypPass = crypto.Compute(_values[1]);
                        u.username = _values[0];
                        u.password = encrypPass;
                        u.passwordsalt = crypto.Salt;
                        u.email = _values[2];
                        u.phone = _values[3];
                        u.adminq = int.Parse(_values[4].ToString());
                        u.ansforaq = _values[5];
                        u.userq = int.Parse(_values[6].ToString());
                        u.ansforuq = _values[7];
                        u.AdminApproved = true;
                        dc.Userinfoes.Add(u);
                        dc.SaveChanges();
                        successrcrd = successrcrd + 1;
                    }
                    else
                    {
                        failedrcrd = failedrcrd + 1;
                    }
                    cssrecords = cssrecords - 1;
                   


            }
           
        }
        //[Authorize]
        [HttpPost]
          public JsonResult bulkUsers(filename fnames)
        {
            //Thread thread = new Thread(WorkThreadFunction);
            if (fnames.Command1 == "Command1")
            {
                List<string> csvvalue = loadCsvFile(fnames.fname);
                cssrecords = csvvalue.Count;

                //ViewBag.Message = "Success";
               
                thread.Start(fnames.fname);
                string FileName = "";
                filename obj = new filename { records = cssrecords };
                return Json(obj, JsonRequestBehavior.AllowGet);
            }
            else
            {
                thread.Abort();
               // cssrecords = -1;
                filename obj = new filename { records = 0 };
                return Json(obj, JsonRequestBehavior.AllowGet);
            }
        }
        public JsonResult getcount()
        {
           
            filename obj = new filename { records = cssrecords, succesrcrds = successrcrd, failedrcrds = failedrcrd };
            return Json(obj, JsonRequestBehavior.AllowGet);
        }
        
        [HttpPost]
        public JsonResult GetUsrEnbledt(Enableusr obj)
        {
            Enableusr usredt = new Enableusr();
            try
            {
                paresetEntities db = new paresetEntities();
                var obj1 = db.Userinfoes.Where(c => c.username == obj.username).First();
               
                usredt.username = obj1.username.ToString();

                usredt.adminapproved = bool.Parse(obj1.AdminApproved.ToString());
                usredt.failuredis = obj1.failurecount;
                usredt.errormsg = "Success";
                return Json(usredt, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                usredt.errormsg = "Error";
                return Json(usredt, JsonRequestBehavior.AllowGet);
            }

        }

      


        [Authorize]
        public ActionResult SignOut()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "Home");
        }
        //[Authorize]
        //public ActionResult Testdomain()
        //{
        //    var directoryEntry = new DirectoryEntry("LDAP://192.168.10.9");
        //    using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "LDAP://192.168.10.9"))
        //    {
        //        // validate the credentials
        //        return pc.ValidateCredentials(Credentials.Username, Credentials.Password);
        //    }
        //}
        public ActionResult SampleDb()
        {

            return View();
        }
        public ActionResult Login()

        {

            return View();
        }
        public ActionResult MyLogin()
        {

            return View();
        }
        public ActionResult UnAuthorized()
        {
            return View();
        }
        [HttpPost]
        public ActionResult Login(LoginViewModel user)

        {
            if ( !String.IsNullOrEmpty(user.username) && !String.IsNullOrEmpty(user.Password))
            {


                if (IsValidAdmin(user.username, user.Password))
                {
                    FormsAuthentication.SetAuthCookie(user.username, false);
                    return RedirectToAction("adminview", "Account");
                }

                {
                    paresetEntities db = new paresetEntities();
                    var user1 = db.Userinfoes.FirstOrDefault(u => u.username == user.username);
                    int count = int.Parse(user1.failurecount.ToString());
                    if (count <= 3)
                    {

                        if (IsValid(user.username, user.Password))
                        {
                            FormsAuthentication.SetAuthCookie(user.username, false);
                            return RedirectToAction("Myprofilewe", "Account");

                        }
                        else
                        {
                            //ModelState.AddModelError("", "Login details are wrong.");
                            ViewBag.Message = "Error";
                        }
                    }
                    else
                    {
                        ViewBag.Message = "Error1";
                    }
                }
            }
            return View();
        }
        public ActionResult Aditmydata()
        {
            return View();
        }
        public ActionResult Registration()
        {
            return View();
        }
        [HttpGet]
        public ActionResult Signup()
        {

            return View(Getusqlist());
        }
        [HttpPost]
        public ActionResult Signup(UserReg user)
        {
            if (user.Username != null && user.Password != null && user.email != null && user.Ansforaq != null && user.Ansforuq != null && user.ConfirmPassword != null)
            {
                //if (DoesUserExist(user.Username))
                //{
                    using (paresetEntities dc = new paresetEntities())
                    {
                        //you should check duplicate registration here
                        var adminq = dc.Admininfoes.FirstOrDefault(u => u.aid == 1);
                        List<string> lstResult = (from table in dc.Userinfoes
                                                  where table.username == user.Username
                                                  select table.password).ToList();
                        if (lstResult.Count == 0)
                        {

                            Userinfo u = new Userinfo();
                            var crypto = new SimpleCrypto.PBKDF2();
                            var encrypPass = crypto.Compute(user.Password);
                            u.username = user.Username;
                            u.password = encrypPass;
                            u.passwordsalt = crypto.Salt;
                            u.email = user.email;
                            u.phone = user.phone;
                            u.adminq = adminq.adminsq;
                            u.ansforaq = user.Ansforaq;
                            u.userq = user.Userq;
                            u.ansforuq = user.Ansforuq;
                            u.AdminApproved = true;
                            u.failurecount = 0;
                            dc.Userinfoes.Add(u);
                            dc.SaveChanges();
                            // ModelState.Clear();
                            user = null;
                            ViewBag.Message = "Success";

                        }
                        else
                        {
                            ViewBag.Message = "Error2";
                        }
                    }
                //}
                //else
                //{
                //    ViewBag.Message = "Invalid user name.";
                //}

            }
            else
            {
                ViewBag.Message = "Error1";
            }

            return View(Getusqlist());
        }

        private bool IsValid(string usernam, string password)
        {
            var crypto = new SimpleCrypto.PBKDF2();
            bool IsValid = false;

            using (var db = new paresetEntities())
            {
            
                var user = db.Userinfoes.FirstOrDefault(u => u.username == usernam);


                if (user != null)
                {
                    if (user.password == crypto.Compute(password, user.passwordsalt))
                    {
                        return true;
                    }
                }
                int count = int.Parse(user.failurecount.ToString());
               
                user.failurecount = count + 1;
                db.Entry(user).CurrentValues.SetValues(user);
                db.SaveChanges();

            }
          
            return IsValid;
        }
        private bool IsValidAdmin(string usernam, string password)
        {
            var crypto = new SimpleCrypto.PBKDF2();
            bool IsValid = false;

            using (var db = new paresetEntities())
            {
                //var user = from u in db.Userinfoes
                //           where u.username == usernam
                //           select u.password;
                //List<string> lstResult = (from table in db.Userinfoes
                //                          where table.username == usernam
                //                          select table.password).ToList();
                var user = db.Admininfoes.FirstOrDefault(u => u.adminname == usernam);

                //if (lstResult.Count != 0)
                //{
                //    string dtStatus = lstResult[0];
                if (user != null)
                {
                    if (user.adminpass == password)
                    {
                        IsValid = true;
                    }
                }
                // }
            }
            return IsValid;
        }

        public ActionResult Forgotpassword()
        {
            WindowsIdentity current = WindowsIdentity.GetCurrent();
            forgotpasswordmodel obj = new forgotpasswordmodel();
            obj.username1 = Environment.UserName;


            return View(obj);
        }
        [HttpPost]
        public ActionResult Forgotpassword(forgotpasswordmodel un)
        {
            if ( !string.IsNullOrEmpty(un.username1))
            {
               
           
            using (var db = new paresetEntities())
            {
                var user = db.Userinfoes.FirstOrDefault(u => u.username == un.username1);
                if (user != null)
                {
                    //var Aq =  db.Chresqlists.FirstOrDefault(u => u.id == user.adminq);
                    //var Uq = db.Chresqlists.FirstOrDefault(u => u.id == user.userq);
                    FormsAuthentication.SetAuthCookie(un.username1, false);
                    return RedirectToAction("authforpswdreset", "Home");
                }
                else
                {
                    ViewBag.Message = "Error";
                }
            }
            }
            else
            {
                ViewBag.Message = "Error1";
            }
            return View();
        }

        public UserReg Getusqlist()
        {
            paresetEntities db = new paresetEntities();


            List<Chresqlist> objcountrylist = (from data in db.Chresqlists
                                               select data).ToList();
            Chresqlist objcountry = new Chresqlist();
            objcountry.Usersqlist = "Select";
            objcountry.id = 0;
            objcountrylist.Insert(0, objcountry);
            SelectList objmodeldata = new SelectList(objcountrylist, "id", "Usersqlist", 0);
            /*Assign value to model*/
            UserReg objcountrymodel = new UserReg();
            objcountrymodel.Usersqlist1 = objmodeldata;
            return objcountrymodel;

        }
        public ActionResult authforpswdreset()
        {

            paresetEntities db = new paresetEntities();
            var mobileno = db.Userinfoes.FirstOrDefault(u => u.username == User.Identity.Name);
            string recipient = mobileno.phone.ToString();
            string masked = "(XXX) XXX-" + recipient.Substring(recipient.Length - 4);
            Userauthtypes obj = new Userauthtypes();
            obj.phone = masked;
            var uemail = db.Userinfoes.FirstOrDefault(u => u.username == User.Identity.Name);
            string recipient1 = uemail.email.ToString();
            //string masked1 = "XXXXXXXX" + recipient1.Substring(recipient1.Length - 10);
            obj.email = recipient1;
            //obj.userauthlist = db.Userauthoptions.ToList();
            //obj.selecttedans = "";
            obj.username = User.Identity.Name.ToString();
            return View(obj);

        }
        [HttpPost]
        public ActionResult authforpswdreset(Userauthtypes uop)

        {
            var ob = uop.selecttedans;
            
            if (ob != null)
               {
                string auth = ob.ToString();
                if (auth == "emailotp")
                {
                    return RedirectToAction("emailotp", "Home");
                }
                if (auth == "smsotp")
                {
                    return RedirectToAction("smsotp", "Home");
                }
                if (auth == "chresposqa")
                {
                    return RedirectToAction("Listofqfora", "Account");
                }
            }
            else
            {
                ViewBag.Message = "Error";
            }

            Userauthtypes obj = new Userauthtypes();

            return View(obj);
        }
        public ActionResult smsotp()
        {

            int otpValue = new Random().Next(100000, 999999);
            var status = "";
          

           
            try
            {
                paresetEntities db = new paresetEntities();
                var mobileno = db.Userinfoes.FirstOrDefault(u => u.username == User.Identity.Name);
                string recipient = mobileno.phone.ToString();
                string masked = "(XXX) XXX-" + recipient.Substring(recipient.Length - 4);
                string APIKey = System.Configuration.ConfigurationManager.AppSettings["APIKey"].ToString();

                string message = "Your OTP Number is " + otpValue + " ( Sent By : nexzip )";
                String encodedMessage = System.Web.HttpUtility.UrlEncode(message);

                using (var webClient = new System.Net.WebClient())
                {
                    byte[] response = webClient.UploadValues("https://api.textlocal.in/send/", new System.Collections.Specialized.NameValueCollection(){

                                         {"apikey" , APIKey},
                                         {"numbers" , recipient},
                                         {"message" , encodedMessage},
                                         {"sender" , "TXTLCL"}});

                    string result = System.Text.Encoding.UTF8.GetString(response);

                    var jsonObject = Newtonsoft.Json.Linq.JObject.Parse(result);

                    status = jsonObject["status"].ToString();

                    Session["CurrentOTP"] = otpValue;
                }


                //return Json(status, JsonRequestBehavior.AllowGet);
                OTPValidater obj = new OTPValidater();
                obj.msakmobilelable = "successfully send otp to you reg mobile number" + masked + status;
                obj.username = User.Identity.Name.ToString();
                return View(obj);

            }
            catch (Exception e)
            {
                OTPValidater obj = new OTPValidater();
                obj.msakmobilelable = "Error";
                obj.username = User.Identity.Name.ToString();
                return View(obj);

            }
        }
        [HttpPost]
        public ActionResult smsotp(OTPValidater oTP)
        {
            string sessionOTP = Session["CurrentOTP"].ToString();

            if (oTP.otpstring == sessionOTP)
            {
                FormsAuthentication.SetAuthCookie(User.Identity.Name, false);
                return RedirectToAction("Setpassword", "Account");

            }
            oTP.msakmobilelable = "Error";
            return View(oTP);
        }
        public ActionResult emailotp()
        {
            int otpValue = new Random().Next(100000, 999999);
            var status = "";
            OTPmailValidater ob = new OTPmailValidater();
            try
            {
                Session["msgotp"] = otpValue;
                //string msg = "your otp from abc.com is " + otpValue;
                paresetEntities db = new paresetEntities();
                var uemail = db.Userinfoes.FirstOrDefault(u => u.username == User.Identity.Name);
                string recipient = uemail.email.ToString();
                string masked = "XXXXXXXX" + recipient.Substring(recipient.Length - 10);
                string emailfrom = System.Configuration.ConfigurationManager.AppSettings["fromemail"].ToString();
                string passwordmail = System.Configuration.ConfigurationManager.AppSettings["Password"].ToString();
                MailMessage msg = new MailMessage();
                msg.From = new MailAddress(emailfrom);
                msg.To.Add(recipient);
                msg.Subject = "Random Password for your Account";
                msg.Body = "Your Random password is:" + otpValue;
                msg.IsBodyHtml = true;
                SmtpClient smt = new SmtpClient();
                smt.Host = "smtp.zoho.com";
                System.Net.NetworkCredential ntwd = new System.Net.NetworkCredential();
                ntwd.UserName = emailfrom; //Your Email ID  
                ntwd.Password = passwordmail; // Your Password  
                smt.UseDefaultCredentials = true;
                smt.Credentials = ntwd;
                smt.Port = 587;
                smt.EnableSsl = true;
                smt.Send(msg);


                ob.msakemaillable = masked;
                ob.username = User.Identity.Name.ToString();
                return View(ob);
            }
            catch (Exception e)
            {
                ob.msakemaillable = "Error";
                ob.username = User.Identity.Name.ToString();
                return View(ob);
            }


        }
        [HttpPost]
        public ActionResult emailotp(OTPmailValidater oTP)  
        {
            string sessionOTP = Session["msgotp"].ToString();

            if (oTP.emailotpstring == sessionOTP)
            {
                FormsAuthentication.SetAuthCookie(User.Identity.Name, false);
                return RedirectToAction("Setpassword", "Account");

            }
            ViewBag.Message = "Error";
            return View(oTP);
        }

            public bool DoesUserExist(string userName)
        {
            SearchResult sr = null;
            paresetEntities dc = new paresetEntities();

            var admind = dc.Admininfoes.FirstOrDefault(u => u.aid == 1);

            string adminUser = admind.adminname;
            string adminPassword = admind.adminpass;
            using (DirectoryEntry de = new DirectoryEntry("LDAP://" + admind.domainip, adminUser, admind.adminpass))
           {
            using (DirectorySearcher sea = new DirectorySearcher(de))
            {
                    //sea.Filter = “(&(objectCategory=user)(samAccountName=” + “\”” + user + “\”” + “))”;
                    //sea.Filter = "(&(objectCategory=person)(objectClass = user)(samAccountName =" + userName + "))";
                    //sr = sea.FindOne();
                  

                    sea.Filter = "(SAMAccountName=" + userName + ")";
                    sea.PropertiesToLoad.Add("cn");
                     sr = sea.FindOne();
                }

            return sr != null ? true : false;
        }
        }

    }
}