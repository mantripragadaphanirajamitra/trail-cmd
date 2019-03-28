using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.Mvc;
using System.Web.Configuration;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using WebApplication2.Models;
using System.Text;
using System.Net;
using WebApplication2.Security;
using System.Linq.Dynamic;
namespace WebApplication2.Controllers
{
   
    public class AccountController : Controller
    {
        [Authorize]
        public ActionResult pwdpolicy()
        {
            try
            {
                paresetEntities db = new paresetEntities();

                var obj = db.Pwdpolicies.ToList();
                Pwdpolicycon options = new Pwdpolicycon();
                options.pwdminlen = bool.Parse(obj[0].Isenabel.ToString());
                options.spclchar = bool.Parse(obj[1].Isenabel.ToString());
                options.capfirst = bool.Parse(obj[2].Isenabel.ToString());
                options.lastpwd = bool.Parse(obj[3].Isenabel.ToString());
                return View(options);



            }

            catch
            {
                ViewBag.Message = "something went wrong";
                return View();
            }

        }
        [Authorize]
        [HttpPost]
        public ActionResult pwdpolicy(Pwdpolicycon pwd)
        {
            try
            {
                paresetEntities db = new paresetEntities();

                var obj = db.Pwdpolicies.ToList();
                obj[0].Isenabel = pwd.pwdminlen;
                obj[1].Isenabel = pwd.capfirst;
                obj[2].Isenabel = pwd.spclchar;
                obj[3].Isenabel = pwd.lastpwd;
                //obj.Emailotp = confauthoptionsobj.emailotp;
                //obj.Charesq = confauthoptionsobj.challengequestions;
                //obj.Smsotp = confauthoptionsobj.smsotp;
                foreach (var m in obj)
                {
                    db.Entry(m).CurrentValues.SetValues(m);
                    db.SaveChanges();
                }

                ModelState.Clear();
                ViewBag.Message = "Success";
                return View(pwd);
            }

            catch(Exception ex)
            {
                ViewBag.Message = "Error";
                return View();
            }
        }
        // GET: Account
        [Authorize]
        public ActionResult changepwdinad()
        {
            return View();
        }
        [Authorize]
        [HttpPost]
        public ActionResult changepwdinad(Changepwrd1 chngepwd)
        {

            try
            {
                paresetEntities db = new paresetEntities();
                var obj = db.Admininfoes.Where(c => c.aid == 1).First();
                string ldapPath = "LDAP://192.168.0.3/DC=nexzipdomain,DC=com";
               // string ldappath = "LDAP://CN=testuser100,CN=Users,DC=nexzipdomain,DC=com";
                DirectoryEntry directionEntry = new DirectoryEntry(ldapPath);
                if (directionEntry != null)

                {
                    directionEntry.AuthenticationType = AuthenticationTypes.Secure;
                    DirectorySearcher search = new DirectorySearcher(directionEntry);
                     string filter =  "(&(objectClass=user)(cn=testuser100))";
                     search.Filter = filter;
                    // string filter = string.Format("(SAMAccountName={0})", User.Identity.Name);
                    // search.Filter = "(SAMAccountName=" + User.Identity.Name + ",CN=Users)";
                    //search.ReferralChasing = ReferralChasingOption.All;
                    SearchResult result = search.FindOne();
                    if (result != null)
                    {
                        DirectoryEntry userEntry = result.GetDirectoryEntry();
                        if (userEntry != null)
                        {
                            userEntry.Invoke("ChangePassword", new object[] { chngepwd.ChangePassword == chngepwd.ConfirmPassword });
                            userEntry.CommitChanges();
                            ViewBag.Message = "Success";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ViewBag.Message = "Error";
            }

            return View();
        }

        [Authorize]
        public ActionResult ChangePassword()
        {


            return View();
        }
        [Authorize]
        [HttpPost]
        public ActionResult ChangePassword(Changepwrd1 changepassword)
        {

            try
            {
                paresetEntities db = new paresetEntities();
                var obj = db.Admininfoes.Where(c => c.aid == 1).First();
                string ldapPath = "LDAP://" + obj.domainip.ToString();
                DirectoryEntry directionEntry = new DirectoryEntry(ldapPath, "nexzipdomain" + "\\" + User.Identity.Name, "password");
                if (directionEntry != null)

                {
                    DirectorySearcher search = new DirectorySearcher(directionEntry);
                    search.Filter = "(SAMAccountName=" + User.Identity.Name + ")";
                    SearchResult result = search.FindOne();
                    if (result != null)
                    {
                        DirectoryEntry userEntry = result.GetDirectoryEntry();
                        if (userEntry != null)
                        {
                            userEntry.Invoke("ChangePassword", new object[] { changepassword.ChangePassword == changepassword.ConfirmPassword });
                            userEntry.CommitChanges();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                ViewBag.Message = "Error";
            }
            return View();
        }
        [Authorize]
        public ActionResult EnableUser()
        {
            return View();
        }
        [Authorize]
        [HttpPost]
        public ActionResult EnableUser(Enableusr enable)
        {
            try
            {
                paresetEntities db = new paresetEntities();
            var obj = db.Userinfoes.Where(c => c.username == enable.username).First();
            obj.failurecount = 0;
            obj.AdminApproved = true;
            db.Entry(obj).CurrentValues.SetValues(obj);
            db.SaveChanges();
                ViewBag.Message = "Success1";

            }
            catch (Exception cex)
            {
                ViewBag.Message = "Error";
            }
            return View();
        }
        public ActionResult GetRegUsers()
        {
            paresetEntities entities = new paresetEntities();
            List<Userinfo> customers = entities.Userinfoes.ToList();
            ViewBag.userinfo = customers;
            return View();
        }
        //write action for return json data
        [HttpPost]
        public JsonResult GetRegUsers1()
        {
            //Get parameters
            //Get start (paging start index) and length (pagesize for paging)
            var draw = Request.Form.GetValues("draw").FirstOrDefault();
            var start = Request.Form.GetValues("start").FirstOrDefault();
            var length = Request.Form.GetValues("length").FirstOrDefault();
            //Get sort columns  value
            var sortColumn = Request.Form.GetValues("columns[" + Request.Form.GetValues("order[0][column]").FirstOrDefault() + "][name]").FirstOrDefault();
            var sortColumnDir = Request.Form.GetValues("order[0][dir]").FirstOrDefault();

            int pagesize = length != null ? Convert.ToInt32(length) : 0;
            int skip = start != null ? Convert.ToInt32(start) : 0;
            int totalRecords = 0;

            using (paresetEntities dc = new paresetEntities())
            {
                var v = (from a in dc.Userinfoes select a);

                //sorting
                if (!(string.IsNullOrEmpty(sortColumn) && string.IsNullOrEmpty(sortColumnDir)))
                {
                    v = v.OrderBy(sortColumn + " " + sortColumnDir);

                }
                totalRecords = v.Count();
                var data = v.Skip(skip).Take(pagesize).ToList();
                return Json(new { draw = draw, recordsFiltered = totalRecords, recordsTotal = totalRecords, data = data }, JsonRequestBehavior.AllowGet);
            
            }
        }
            
       
        [Authorize]
        public ActionResult Myprofile()
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
            List<Userinfo> lstResult = (from data1 in db.Userinfoes where data1.username == User.Identity.Name select data1).ToList();
            UserReg objcountrymodel = new UserReg();
            objcountrymodel.Username = lstResult[0].username;
            objcountrymodel.Password = lstResult[0].password;
            objcountrymodel.email = lstResult[0].email;
            objcountrymodel.phone = lstResult[0].phone;
            objcountrymodel.Adinq = int.Parse(lstResult[0].adminq.ToString());
            var Adminqst = db.Chresqlists.FirstOrDefault(u => u.id == objcountrymodel.Adinq); 
            objcountrymodel.Adinqs = Adminqst.Adminsqlist.ToString();
           
            objcountrymodel.Ansforaq = lstResult[0].ansforaq;
            objcountrymodel.Userq = int.Parse(lstResult[0].userq.ToString());
            objcountrymodel.Ansforuq = lstResult[0].ansforuq;
            objcountrymodel.Usersqlist1 = objmodeldata;
            return View(objcountrymodel);
        }
        [HttpPost]
        [Authorize]
        public ActionResult Myprofile(UserReg user)
        {
            paresetEntities db = new paresetEntities();
            var obj = db.Userinfoes.Where(c => c.username == user.Username).First();
            try
            {
                
                obj.username = user.Username;
                obj.email = user.email;
                //obj.adminq = user.Adinq;
                obj.ansforaq = user.Ansforaq;
                obj.userq = user.Userq;
                obj.ansforuq = user.Ansforuq;
                obj.phone = user.phone;
                //user.password = obj.password;
                //  user.Userq = (int)obj.userq;
                db.Entry(obj).CurrentValues.SetValues(obj);
                db.SaveChanges();
                ModelState.Clear();
                ViewBag.Message = "Success";
             }
            catch (Exception cex)
            {
                ViewBag.Message = "Error";
               
            }
            return View(GetusqlistA());
        }

        public ActionResult Myprofilewe()
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
            List<Userinfo> lstResult = (from data1 in db.Userinfoes where data1.username == User.Identity.Name select data1).ToList();
            UserReg objcountrymodel = new UserReg();
            objcountrymodel.Username = lstResult[0].username.ToString();
            objcountrymodel.Password = lstResult[0].password;
            objcountrymodel.email = lstResult[0].email;
            objcountrymodel.phone = lstResult[0].phone;
            objcountrymodel.Adinq = int.Parse(lstResult[0].adminq.ToString());
            var Adminqst = db.Chresqlists.FirstOrDefault(u => u.id == objcountrymodel.Adinq);
            objcountrymodel.Adinqs = Adminqst.Adminsqlist.ToString();
            objcountrymodel.Ansforaq = lstResult[0].ansforaq;
            objcountrymodel.Userq = int.Parse(lstResult[0].userq.ToString());
            var user = db.Chresqlists.FirstOrDefault(u => u.id == objcountrymodel.Userq);
         

            objcountrymodel.Userqs = user.Usersqlist;
            objcountrymodel.Ansforuq = lstResult[0].ansforuq;
            objcountrymodel.Usersqlist1 = objmodeldata;
            return View(objcountrymodel);
        }
        [Authorize]
        public ActionResult Listofqfora()
        {

            using (var db = new paresetEntities())
            {
                var user = db.Userinfoes.FirstOrDefault(u => u.username == User.Identity.Name);
                if (user != null)
                {
                    var Aq = db.Chresqlists.FirstOrDefault(u => u.id == user.adminq);
                    var Uq = db.Chresqlists.FirstOrDefault(u => u.id == user.userq);
                    Ansforuserq afq = new Ansforuserq();
                    afq.AdminQ = Aq.Adminsqlist;
                    afq.UserQ = Aq.Usersqlist;
                    afq.UsernA = user.username;
                    // FormsAuthentication.SignOut();
                    afq.username1 = User.Identity.Name.ToString();
                    return View(afq);
                }
            }
            return View();
        }
        [HttpPost]
        [Authorize]
        public ActionResult Listofqfora(Ansforuserq Ansfuq, String Command)
        {
            if (Command == "Next")
            {
                Ansforuserq afq = new Ansforuserq();
                var db = new paresetEntities();
                if (Ansfuq.AnsforAdminQ != null && Ansfuq.AnsforUserQ != null)
                {
                    var user = db.Userinfoes.FirstOrDefault(u => u.username == User.Identity.Name);
                    if (user != null)
                    {
                        if (user.ansforaq == Ansfuq.AnsforAdminQ && user.ansforuq == Ansfuq.AnsforUserQ)
                        {
                            FormsAuthentication.SetAuthCookie(user.username, false);
                            return RedirectToAction("Setpassword", "Account");
                        }
                    }


                }
                var user1 = db.Userinfoes.FirstOrDefault(u => u.username == User.Identity.Name);
                if (user1 != null)
                {
                    var Aq = db.Chresqlists.FirstOrDefault(u => u.id == user1.adminq);
                    var Uq = db.Chresqlists.FirstOrDefault(u => u.id == user1.userq);

                    afq.AdminQ = Aq.Adminsqlist;
                    afq.UserQ = Aq.Usersqlist;
                    afq.UsernA = user1.username;
                    afq.AnsforAdminQ = "";
                    afq.AnsforUserQ = "";
                    // FormsAuthentication.SignOut();
                    // return View(afq);
                }
                ViewBag.Message = "Error";
                return View(afq);
            }
            else
            {
                return RedirectToAction("Login", "Home");
            }
        }
        [Authorize]
        [Authorize]
        public ActionResult Setpassword()
        {
            Account obj = new Account();
            obj.username = User.Identity.Name.ToString();
            paresetEntities db = new paresetEntities();
            obj.plist = db.Pwdpolicies.ToList();
            //List<Pwdpolicy> pwds = db.Pwdpolicies.ToList();
            //foreach(var mb in pwds)
            //                    {
            //    if (mb.Isenabel)
            //    {
            //        obj.policylbl = obj.policylbl + Environment.NewLine + mb.Label.ToString();
                    
            //    }
            //}
            return View(obj);
        }
       
        [HttpPost]
        [Authorize]
        public ActionResult Setpassword(Account set, String Command)
        {
            if (Command == "ResetPassword")
            {
                if ((0 == String.Compare(set.password, set.Confirmpassword, true)))
                {


                    string username = User.Identity.Name;
                    paresetEntities dc = new paresetEntities();
                    
                    var admind = dc.Admininfoes.FirstOrDefault(u => u.aid == 1);

                    string adminUser = admind.adminname;
                    string adminPassword = admind.adminpass;
                    string fullPath = "LDAP://" + admind.domainip;
                    try
                    {

                        DirectoryEntry entry = new DirectoryEntry(fullPath, adminUser, adminPassword);
                        //var directoryEntry = GetDirectoryEntryByUserName(username);
                        DirectorySearcher dirSearcher = new DirectorySearcher(entry);
                        string filter = string.Format("(SAMAccountName={0})", username);
                        dirSearcher.Filter = filter;
                        SearchResult result = dirSearcher.FindOne();
                        if (result != null)
                        {




                            DirectoryEntry userEntry = result.GetDirectoryEntry();

                            //Enable Account if it is disabled
                            userEntry.Properties["userAccountControl"].Value = 0x200;
                            //Reset User Password
                            userEntry.Invoke("SetPassword", new object[] { set.password });
                            //Force user to change password at next logon
                            //userEntry.Properties["pwdlastset"][0] = 1; ////////////to be modified
                            userEntry.CommitChanges();
                            userEntry.Close();



                        }
                       
                        useraudit obj = new useraudit();
                        obj.UserName = username;
                        string ip = Dns.GetHostEntry(Dns.GetHostName()).AddressList[1].ToString();
                        obj.ipaddress = ip;
                        DateTime now = DateTime.Now.ToLocalTime();
                        obj.paswordchangedate = now;
                        dc.useraudits.Add(obj);
                        dc.SaveChanges();



                        ViewBag.Message = "Success";

                    }



                    catch (Exception ex)
                    {

                        if (ex.HResult == -2146232828)
                        {
                            ViewBag.Message = "Error3";
                        }
                        else
                        {
                            //not authenticated due to some other exception [this is optional]
                            ViewBag.Message = "Error2";
                        }
                    }
                }
                else
                {
                    ViewBag.Message = "Error1";
                }
                paresetEntities dc1 = new paresetEntities();
                Account obj1 = new Account();
                obj1.username = User.Identity.Name.ToString();
                obj1.plist = dc1.Pwdpolicies.ToList();
                return View(obj1);
            }
            else
            {
                FormsAuthentication.SignOut();
                return RedirectToAction("Login", "Home");
            }
       }

        //[Authorize]
        [AuthorizeRoles("Admin")]
        public ActionResult SelectAdmiqforuser()
        {
            Admindetails objcountrymodel1 = new Admindetails();
            objcountrymodel1.Adminsqlist = GetAsqlist();
            paresetEntities db = new paresetEntities();
            var Aq = db.Admininfoes.FirstOrDefault(u => u.aid == 1);
            var Aq1 = db.Chresqlists.FirstOrDefault(u => u.id == Aq.adminsq);
            objcountrymodel1.AdminSqaslbl = Aq1.Adminsqlist.ToString();
            return View(objcountrymodel1);
           
        }
        [HttpPost]
        [AuthorizeRoles("Admin")]
        public ActionResult SelectAdmiqforuser(Admindetails admind)
        {
            paresetEntities db = new paresetEntities();
            var obj = db.Admininfoes.Where(c => c.adminname == User.Identity.Name).First();
            obj.adminsq = admind.AdminSq;


            db.Entry(obj).CurrentValues.SetValues(obj);
            db.SaveChanges();
            ModelState.Clear();
            ViewBag.Message = "Success";
            Admindetails objcountrymodel1 = new Admindetails();
            objcountrymodel1.Adminsqlist = GetAsqlist();
            var Aq1 = db.Chresqlists.FirstOrDefault(u => u.id == admind.AdminSq);
            objcountrymodel1.AdminSqaslbl = Aq1.Adminsqlist.ToString();
          
            return View(objcountrymodel1);
        }
        [AuthorizeRoles("Admin")]
        public ActionResult GetADusers()
        {
            paresetEntities r = new paresetEntities();
            var data = r.UsersinADs.ToList();
            ViewBag.userdetails = data;
            return View();
        }
        [AuthorizeRoles("Admin")]
        public ActionResult GetRecentpasswordrests()
        {
            paresetEntities r = new paresetEntities();
            var data = r.useraudits.ToList();
            ViewBag.userdetails1 = data;
            return View();
        }

        [AuthorizeRoles("Admin")]
        public ActionResult UpdateusersfromAD()
        {
            return View();
        }
        [HttpPost]
        [AuthorizeRoles("Admin")]
        public ActionResult UpdateusersfromAD(string  ad  )
        {
            // List<Users> lstADUsers = new List<Users>();
            paresetEntities dc = new paresetEntities();
            var admind = dc.Admininfoes.FirstOrDefault(u => u.adminname == User.Identity.Name);
            //var name = from i in dc.Admininfoes
            //           where i.adminname == User.Identity.Name
            //           select i.domainip;
           
            //var name1 = from i in dc.Admininfoes
            //           where i.adminname == User.Identity.Name
            //           select i.adminpass;

            // string DomainPath = "LDAP://192.168.10.11";
            string DomainPath = "LDAP://"+ admind.domainip;
           
            string adminpassw = admind.adminpass;
            try
            {
                DirectoryEntry searchRoot = new DirectoryEntry(DomainPath, User.Identity.Name, adminpassw);
                DirectorySearcher search = new DirectorySearcher(searchRoot);

                // search.Filter = "(&(objectClass=user)(objectCategory=person))";
                search.Filter = "(&(objectClass=person)(objectCategory=user))";
                //search.Filter = "(&(objectClass=Users))";
                search.PropertiesToLoad.Add("sAMAccountname");
                search.PropertiesToLoad.Add("mail");
                search.PropertiesToLoad.Add("usergroup");
                search.PropertiesToLoad.Add("name");//first name
                SearchResult result;
                SearchResultCollection resultCol = search.FindAll();
                if (resultCol != null)
                {
                    for (int counter = 0; counter < resultCol.Count; counter++)
                    {
                        string UserNameEmailString = string.Empty;
                        result = resultCol[counter];
                        if (result.Properties.Contains("sAMAccountname") &&
                                 result.Properties.Contains("mail") &&
                            result.Properties.Contains("name"))
                        {
                            UsersinAD objSurveyUsers = new UsersinAD();
                            objSurveyUsers.Email = (String)result.Properties["mail"][0];
                             
                            objSurveyUsers.UserName = (String)result.Properties["samaccountname"][0];
                            objSurveyUsers.DisplayName = (String)result.Properties["name"][0];
                            // objSurveyUsers.Isregistered = 0;
                            //you should check duplicate registration here
                            List<string> lstResult = (from table in dc.UsersinADs
                                                      where table.UserName == objSurveyUsers.UserName
                                                      select table.UserName).ToList();
                            if (lstResult.Count == 0)
                            {
                                dc.UsersinADs.Add(objSurveyUsers);
                                dc.SaveChanges();
                            }

                        }
                    }
                    ViewBag.Message = "Success";
                }
            }
            catch (DirectoryServicesCOMException cex)
            {
                //not authenticated; reason why is in cex
                ViewBag.Message = "Error";
            }
            catch (Exception ex)
            {
                //not authenticated due to some other exception [this is optional]
                ViewBag.Message = "Error";
            }

            return View();
        }
        [AuthorizeRoles("Admin")]
        public ActionResult adminviewwe()
        {
            paresetEntities db = new paresetEntities();

            List<Admininfo> lstResult = (from data2 in db.Admininfoes where data2.adminname == User.Identity.Name select data2).ToList();
            Admindetails objcountrymodel1 = new Admindetails();
            objcountrymodel1.serveradminname = lstResult[0].serveradminname;
            objcountrymodel1.serveradminpass = lstResult[0].serveradminpass;
            objcountrymodel1.DomainName = lstResult[0].dmainname;
            objcountrymodel1.DomainIP = lstResult[0].domainip;
            // objcountrymodel1.Adminsqlist = GetAsqlist();
            return View(objcountrymodel1);

        }
        [AuthorizeRoles("Admin")]
        public ActionResult adminview()
        {
            paresetEntities db = new paresetEntities();            
           
            List<Admininfo> lstResult = (from data2 in db.Admininfoes where data2.adminname == User.Identity.Name select data2).ToList();
            Admindetails objcountrymodel1 = new Admindetails();
            objcountrymodel1.serveradminname = lstResult[0].serveradminname;
            objcountrymodel1.serveradminpass = lstResult[0].serveradminpass;
            objcountrymodel1.DomainName = lstResult[0].dmainname;            
            objcountrymodel1.DomainIP = lstResult[0].domainip;
           // objcountrymodel1.Adminsqlist = GetAsqlist();
            return View(objcountrymodel1);
            
        }
        [HttpPost]
        [AuthorizeRoles("Admin")]
        public ActionResult adminview( Admindetails Admind ,String Command)
        {
            if (Command == "Update")
            {
                if (Admind.serveradminname != null && Admind.serveradminpass != null && Admind.DomainName != null && Admind.DomainIP != null)
                {
                    IPAddress ip;
                    bool ValidateIP = IPAddress.TryParse(Admind.DomainIP, out ip);
                   
                    if (ValidateIP)
                    {


                        paresetEntities db = new paresetEntities();
                        var obj = db.Admininfoes.Where(c => c.adminname == User.Identity.Name).First();
                        obj.serveradminname = Admind.serveradminname;
                        obj.serveradminpass = Admind.serveradminpass;
                        // obj.adminsq = Admind.AdminSq;
                        obj.dmainname = Admind.DomainName;
                        obj.domainip = Admind.DomainIP;

                        db.Entry(obj).CurrentValues.SetValues(obj);
                        db.SaveChanges();
                        //ModelState.Clear();
                        ViewBag.Message = "Success1";
                    }
                }

            }
            else
            {
                try
                {
                    DirectoryEntry entry = new DirectoryEntry("LDAP://"+ Admind.DomainIP, Admind.serveradminname, Admind.serveradminpass);
                    object nativeObject = entry.NativeObject;
                    ViewBag.Message = "Success2";
                }
                catch (DirectoryServicesCOMException cex)
                {
                    //not authenticated; reason why is in cex
                    ViewBag.Message = "Error";
                }
                catch (Exception ex)
                {
                    //not authenticated due to some other exception [this is optional]
                    ViewBag.Message = "Error";
                }

            }
            //Admindetails objcountrymodel1 = new Admindetails();
            //objcountrymodel1.Adminsqlist = GetAsqlist();
            //return View(objcountrymodel1);
            return View();
        }
        //[Authorize]
        //public ActionResult Testdomain(Admindetails add)
        //{
        //    var directoryEntry = new DirectoryEntry("LDAP://192.168.10.9");
        //    using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "LDAP://192.168.10.9"))
        //    {
        //        // validate the credentials
        //        bool v= pc.ValidateCredentials(add.Adminname,add.Adminpassword);
        //    }
        //    return View();
        //}
        [AuthorizeRoles("Admin")]
        public ActionResult changeuserpass()
        {
            return View();
        }
        [HttpPost]
        [AuthorizeRoles("Admin")]
        public ActionResult changeuserpass(Passwordchange A)
        {
           // var crypto = new SimpleCrypto.PBKDF2();
           

            using (var db = new paresetEntities())
            {
                if (A.ChangePassword == A.ConfirmPassword)
                {
                
                    var user = db.Userinfoes.FirstOrDefault(u => u.username == A.Username);

              



                    if (user != null)
                    {

                        var crypto = new SimpleCrypto.PBKDF2();
                        var encrypPass = crypto.Compute(A.ChangePassword);
                        user.password = encrypPass;
                        user.passwordsalt = crypto.Salt;
                        db.Entry(user).CurrentValues.SetValues(A);
                        db.SaveChanges();
                        ModelState.Clear();
                        ViewBag.Message = "Success";
                    }
                    else
                    {
                        ViewBag.Message = "Error1";

                    }
                }
               else
                {
                    ViewBag.Message = "Error2";

                }
            }
            return View();
        }
        [AuthorizeRoles("Admin")]
        public ActionResult configauthoptions()
        {
            try
            {
                paresetEntities db = new paresetEntities();

                var obj = db.Userauthoptions.ToList();
                checkboxforauthoptions options = new checkboxforauthoptions();
                options.Email = bool.Parse(obj[0].Isenabel.ToString());
                options.smsotp = bool.Parse(obj[1].Isenabel.ToString());
                options.challengeqs = bool.Parse(obj[2].Isenabel.ToString());
                return View(options);

                

            }

            catch
            {
                ViewBag.Message = "please select to update";
                return View();
            }
        }
        
        [HttpPost]

        [AuthorizeRoles("Admin")]
        public ActionResult configauthoptions(checkboxforauthoptions confauthoptionsobj)
        {
            try
            {
                paresetEntities db = new paresetEntities();

                var obj = db.Userauthoptions.ToList();
                obj[0].Isenabel = confauthoptionsobj.Email;
                obj[1].Isenabel = confauthoptionsobj.smsotp;
                obj[2].Isenabel = confauthoptionsobj.challengeqs;

                //obj.Emailotp = confauthoptionsobj.emailotp;
                //obj.Charesq = confauthoptionsobj.challengequestions;
                //obj.Smsotp = confauthoptionsobj.smsotp;
                foreach(var m in obj )
                {
                    db.Entry(m).CurrentValues.SetValues(m);
                    db.SaveChanges();
                }
               
                ModelState.Clear();
                ViewBag.Message = "Success";
                return View(confauthoptionsobj);
            }

            catch
            {
                ViewBag.Message = "Error";
                return View();
            }
            
        }
        //public static DirectoryEntry GetDirectoryEntryByUserName(string userName)
        //{
        //    var de = GetDirectoryObject("192.168.10.11");
        //    var deSearch = new DirectorySearcher(de)
        //    { SearchRoot = de, Filter = "(&(objectCategory=user)(cn=" + userName + "))" };

        //    var results = deSearch.FindOne();
        //    return results != null ? results.GetDirectoryEntry() : null;
        //}

        //private static string GetDomain()
        //{
        //    string adDomain = WebConfigurationManager.AppSettings["adDomainFull"];

        //    var domain = new StringBuilder();
        //    string[] dcs = adDomain.Split('.');
        //    for (var i = 0; i < dcs.GetUpperBound(0) + 1; i++)
        //    {
        //        domain.Append("DC=" + dcs[i]);
        //        if (i < dcs.GetUpperBound(0))
        //        {
        //            domain.Append(",");
        //        }
        //    }
        //    return domain.ToString();
        //}

        //private static DirectoryEntry GetDirectoryObject(string domainReference)
        //{
        //    //string adminUser = WebConfigurationManager.AppSettings["administrator"];
        //    //string adminPassword = WebConfigurationManager.AppSettings["Passw0rd"];
        //    string adminUser = "administrator";
        //    string adminPassword = "Passw0rd";
        //    string fullPath = "LDAP://" + domainReference;

        //    var directoryEntry = new DirectoryEntry(fullPath, adminUser, adminPassword, AuthenticationTypes.Secure);
        //    return directoryEntry;
        //}
        public UserReg GetusqlistA()
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
        public SelectList GetAsqlist()
        {
            paresetEntities db = new paresetEntities();


            List<Chresqlist> objcountrylist = (from data in db.Chresqlists
                                               select data).ToList();
            Chresqlist objcountry = new Chresqlist();
            objcountry.Usersqlist = "Select";
            objcountry.id = 0;
            objcountrylist.Insert(0, objcountry);
            SelectList objmodeldata = new SelectList(objcountrylist, "id", "Adminsqlist", 0);
            /*Assign value to model*/
            //Admindetails adminde = new Admindetails();
            //adminde.Adminsqlist = objmodeldata;
            return objmodeldata;

        }
       

    }
}