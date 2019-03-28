using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using Compare = System.ComponentModel.DataAnnotations.CompareAttribute;


using System.ComponentModel.DataAnnotations;

namespace WebApplication2.Models
{
    public class OTPValidater
    {
        [Display(Name = "successfully send otp to you reg mobile number")]
        public string msakmobilelable { get; set; }
        [Display(Name = "Enter OTP ")]
        public string otpstring { get; set; }
        public String username { get; set; }
    }
    
    public class OTPmailValidater
    {
        [Display(Name = "successfully send otp to you reg email number")]
        public string msakemaillable { get; set; }
        [Display(Name = "Enter OTP ")]
        public string emailotpstring { get; set; }
        public string username { get; set; }
    }

    public class UserReg
    {

        public string adminselq
        {
            get
            {
                paresetEntities db = new paresetEntities();
                var user = db.Admininfoes.FirstOrDefault(u => u.aid == 1);

                var val1 = db.Chresqlists.FirstOrDefault(u => u.id == user.adminsq);

                return val1.Adminsqlist.ToString();
            }

        }


        [Required(ErrorMessage = "Please provide username", AllowEmptyStrings = false)]
        public string Username { get; set; }
        [Required(ErrorMessage = "Please provide Password", AllowEmptyStrings = false)]
        [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        [StringLength(50, MinimumLength = 8, ErrorMessage = "Password must be 8 char long.")]
        [Display(Name = "Password")]
        public string Password { get; set; }
        [Compare("Password", ErrorMessage = "Confirm password dose not match.")]
        [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        public string ConfirmPassword { get; set; }
        [Required(ErrorMessage = "Please provide email", AllowEmptyStrings = false)]
        [RegularExpression(@"^([0-9a-zA-Z]([\+\-_\.][0-9a-zA-Z]+)*)+@(([0-9a-zA-Z][-\w]*[0-9a-zA-Z]*\.)+[a-zA-Z0-9]{2,3})$",
            ErrorMessage = "Please provide valid email id")]
        [Display(Name = "Email")]
        public string email { get; set; }
        [Display(Name = "Phone")]
        public string phone { get; set; }

        public int Adinq { get; set; }
        public string Adinqs { get; set; }
        [Required(ErrorMessage = "Please provide answer", AllowEmptyStrings = false)]
        public string Ansforaq { get; set; }
        public int Userq { get; set; }
        public string Userqs { get; set; }
        [Display(Name = "Answer")]
        [Required(ErrorMessage = "Please provide answer", AllowEmptyStrings = false)]
        public string Ansforuq { get; set; }
        public SelectList Usersqlist1 { get; set; }

        public bool IsUserInRole(string loginName, string roleName)
        {
            using (paresetEntities db = new paresetEntities())
            {
                Admininfo SU = db.Admininfoes.Where(o => o.adminname.ToLower().Equals(loginName))?.FirstOrDefault();
                if (SU != null)
                {
                    //var roles = from q in db.SYSUserRoles
                    //            join r in db.LOOKUPRoles on q.LOOKUPRoleID equals r.LOOKUPRoleID
                    //            where r.RoleName.Equals(roleName) && q.SYSUserID.Equals(SU.SYSUserID)
                    //            select r.RoleName;

                    //if (roles != null)
                    //{
                    //    return roles.Any();
                    //}
                    return true;
                }

                return false;
            }
        }
    }

    public class LoginViewModel
    {
        [Required]
        [Display(Name = "User Name")]       
        public string username { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

       
    }

    public class Userauthtypes
    {
        public List<Userauthoption> userauthlist
        {
            get
            {
                paresetEntities db = new paresetEntities();
                return db.Userauthoptions.ToList();
                
            }
        }
        public string selecttedans { get; set; }
        public string username { get; set; }
        public string phone { get; set; }
        public string email { get; set; }

        
    }
    public class forgotpasswordmodel
    {
        [Required]
        [Display(Name = "User Name")]       
        public string username1 { get; set; }
            


    }
    public class Ansforuserq
    {
        public string UsernA { get; set; }
        public string UserQ { get; set; }
        public string AdminQ { get; set; }
        [Required(ErrorMessage = "Please provide Answer", AllowEmptyStrings = false)]
        [Display(Name = "Answer for Admin Question")]
        public string AnsforAdminQ { get; set; }
        [Required(ErrorMessage = "Please provide Answer", AllowEmptyStrings = false)]
        [Display(Name = "Answer for User Question")]
        public string AnsforUserQ { get; set; }
        public string username1 { get; set; }


    }
    public class userinffrpwdrst
    {
        public string username { get; set; }
        public string email { get; set; }
        public string emailotp { get; set; }
        public string phone { get; set; }
        public string smsotp { get; set; }
    }
  
    //public class Setpasswordw
    //{

    //    [Required(ErrorMessage = "Please provide Password", AllowEmptyStrings = false)]
    //    [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
    //    [StringLength(50, MinimumLength = 8, ErrorMessage = "Password must be 8 char long.")]
    //    public string passwordforset { get; set; }
    //    [Compare("password", ErrorMessage = "Confirm password dose not match.")]
    //    [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
    //    public string Confirmpasswordforset { get; set; }
    //}

}