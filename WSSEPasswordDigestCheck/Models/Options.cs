using CommandLine.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WSSEPasswordDigestCheck.Models
{
    class Options
    {
        [RequiredArgument(0, "source", "Source file to be checked")]
        public string Source { get; set; }

        [RequiredArgument(1, "password", "Clear text password to be used to calculate the PasswordDigest")]
        public string Password { get; set; }
    }
}
