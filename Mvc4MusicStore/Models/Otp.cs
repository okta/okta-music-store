using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace Mvc4MusicStore.Models
{
    public class Otp
    {
        [Required(ErrorMessage = "You must enter a 6 digit pass code")]
        [RegularExpression(@"[0-9]{6}", ErrorMessage = "You must enter a 6 digit pass code")]
        [DisplayName("One-time pass code")]
        public string passCode { get; set; }
    }
}
