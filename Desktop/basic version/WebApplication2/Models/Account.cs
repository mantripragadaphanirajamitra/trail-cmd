using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using System.ComponentModel.DataAnnotations;
using Compare = System.ComponentModel.DataAnnotations.CompareAttribute;
namespace WebApplication2.Models
{
    public class Account
    {

        [Required(ErrorMessage = "Please provide Password", AllowEmptyStrings = false)]
        [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        [StringLength(50, MinimumLength = 8, ErrorMessage = "Password must be 8 char long.")]
        public string password { get; set; }
        [Compare("password", ErrorMessage = "Confirm password dose not match.")]
        [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        public string Confirmpassword { get; set; }
        public string username { get; set; }
        public string policylbl { get; set; }
        public List<Pwdpolicy> plist;
    }
    public class Admindetails
    {
        [Required(ErrorMessage = "Please provide adminname", AllowEmptyStrings = false)]
        public string AdminName { get; set; }
        [Required(ErrorMessage = "Please provide admin Password", AllowEmptyStrings = false)]
        [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        [StringLength(50, MinimumLength = 8, ErrorMessage = "Password must be 8 char long.")]
        public string AdminPassword { get; set; }
        //[Compare("password", ErrorMessage = "Confirm password dose not match.")]
        //[DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        //public string Confirmpassword { get; set; }
        public int AdminSq { get; set; }
        public string AdminSqaslbl { get; set; }
        [Required(ErrorMessage = "Please provide Domainname", AllowEmptyStrings = false)]
        public string DomainName { get; set; }
        [Required(ErrorMessage = "Please provide Domainip", AllowEmptyStrings = false)]
        [RegularExpression(@"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")]
       
        public string DomainIP { get; set; }
        
        public SelectList Adminsqlist { get; set; }
        public string serveradminname { get; set; }
        public string serveradminpass { get; set; }
    }
    public class Passwordchange
    {
        [Required(ErrorMessage = "Please provide username", AllowEmptyStrings = false)]
        public string Username { get; set; }
        [Required(ErrorMessage = "Please provide  Password for user", AllowEmptyStrings = false)]
        [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        [StringLength(50, MinimumLength = 8, ErrorMessage = "Password must be 8 char long.")]
        public string ChangePassword { get; set; }
        public string ConfirmPassword { get; set; }


    }
    //public class Configauthoptions

    //{
    //    [Display(Name = "please select emailotp")]

    //    public  bool emailotp { get; set; }
    //    [Display(Name = "please select smsotp")]
    //    public  bool smsotp { get; set; }
    //    [Display(Name = "please select challengequestions ")]
    //    public  bool challengequestions { get; set; }
    
    //}

    public class ADUsers
    {
        public string Email { get; set; }
        public string UserName { get; set; }
        public string DisplayName { get; set; }
        public bool isMapped { get; set; }
    }
    public class checkboxforauthoptions
    {
        public bool Email { get; set; }
        public bool smsotp { get; set; }
        public bool challengeqs { get; set; }
       
    }
    public class Changepwrd1
    {
        public string LastPassword { get; set; }
        public string ChangePassword { get; set; }
        public string ConfirmPassword { get; set; }
    }
    public class filename
    {
        public string fname { get; set; }
        public int records { get; set; }
        public int succesrcrds { get; set; }
        public int failedrcrds { get; set; }
        public string Command1 { get; set; }
        
    }
    public class Enableusr
    {
        public string username { get; set; }
        public bool failurecount { get; set; }
        public bool adminapproved { get; set; }
        public int failuredis { get; set; }
        public string errormsg { get; set; }
    }
    public class Pwdpolicycon
    {
        public bool pwdminlen { get; set; }
        public bool capfirst { get; set; }
        public bool spclchar { get; set; }
        public bool lastpwd { get; set; }
    }


    


}
