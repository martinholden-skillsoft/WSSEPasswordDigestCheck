using CommandLine;
using OutputColorizer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using WSSEPasswordDigestCheck.Models;

namespace WSSEPasswordDigestCheck
{
    /// <summary>
    /// 
    /// </summary>
    class Program
    {
        /// <summary>
        /// Gets the request.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <returns></returns>
        static Request GetRequest(string source)
        {
            Colorizer.WriteLine("[Green!Extracting Values from {0}]", source);
            //Extract the information from the XML
            XmlDocument Doc = new XmlDocument();
            Doc.PreserveWhitespace = false;
            Doc.Load(source);

            return new Request(Doc);
        }

        /// <summary>
        /// Calculates the digest.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        static byte[] CalculateDigest(Request request, string password)
        {
            //Generate the PasswordDigest
            // get other operands to the right format
            byte[] time = Encoding.UTF8.GetBytes(request.userNameToken.Created);
            byte[] pwd = Encoding.UTF8.GetBytes(password);
            byte[] operand = new byte[request.userNameToken.NonceBytes.Length + time.Length + pwd.Length];

            Array.Copy(request.userNameToken.NonceBytes, operand, request.userNameToken.NonceBytes.Length);
            Array.Copy(time, 0, operand, request.userNameToken.NonceBytes.Length, time.Length);
            Array.Copy(pwd, 0, operand, request.userNameToken.NonceBytes.Length + time.Length, pwd.Length);

            // create the hash
            SHA1 sha1 = SHA1.Create();
            byte[] hash = sha1.ComputeHash(operand);
            return hash;
        }


        /// <summary>
        /// Validates the request.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        static bool ValidateRequest(Request request)
        {
            Colorizer.WriteLine("[White!Validating Request]");
            
            //Check the timestamp is first element
            if (!request.timeStampFirst)
            {
                Colorizer.WriteLine("[Red!Timestamp must be first element in wsse:Security]");
                return false;
            } else
            {
                Colorizer.WriteLine("[Green!Timestamp is first element in wsse:Security]");
            }


            //Check we have TimeStamp Values
            if (request.timeStamp.CreatedDateTime ==null)
            {
                Colorizer.WriteLine("[Red!Request Timestamp Created Value Invalid. Value: {0}]", request.timeStamp.Created);
                return false;
            } else
            {
                Colorizer.WriteLine("[Green!Request Timestamp Created Value Valid]");
            }

            if (request.timeStamp.ExpiresDateTime == null)
            {
                Colorizer.WriteLine("[Red!Request Timestamp Expires Value Invalid. Value: {0}]", request.timeStamp.Expires);
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request Timestamp Expires Value Valid]");
            }

            //Check UserNameToken
            if (request.userNameToken.CreatedDateTime == null)
            {
                Colorizer.WriteLine("[Red!Request UserNameToken Created Value Invalid. Value: {0}]", request.userNameToken.Created);
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request UserNameToken Created Value Valid]");
            }

            if (String.IsNullOrEmpty(request.userNameToken.Username))
            {
                Colorizer.WriteLine("[Red!Request UserNameToken Username Value Is Null Or Empty.]");
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request UserNameToken Username Value present]");
            }

            if (String.IsNullOrEmpty(request.userNameToken.Password))
            {
                Colorizer.WriteLine("[Red!Request UserNameToken Password Is Null Or Empty.]");
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request UserNameToken Password value present.]");
            }

            if (request.userNameToken.PasswordType != "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest")
            {
                Colorizer.WriteLine("[Red!Request UserNameToken Password Type not PasswordDigest. Value: {0}]", request.userNameToken.PasswordType);
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request UserNameToken Password Type Valid]");
            }
           
            if (request.userNameToken.PasswordBytes == null)
            {
                Colorizer.WriteLine("[Red!Request UserNameToken Password value is not valid BASE64 string. Value: {0}]", request.userNameToken.Password);
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request UserNameToken Password value is valid BASE64 string]");
            }

            if (String.IsNullOrEmpty(request.userNameToken.Nonce))
            {
                Colorizer.WriteLine("[Red!Request UserNameToken Nonce Is Null Or Empty.]");
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request UserNameToken Nonce value present.]");
            }

            if (request.userNameToken.NonceEncodingType != "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
            {
                Colorizer.WriteLine("[Red!Request UserNameToken Nonce Type not Base64Binary. Value: {0}]", request.userNameToken.PasswordType);
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request UserNameToken Nonce Type Valid]");
            }

            if (request.userNameToken.NonceBytes == null)
            {
                Colorizer.WriteLine("[Red!Request UserNameToken Nonce value is not valid BASE64 string. Value: {0}]", request.userNameToken.Nonce);
                return false;
            }
            else
            {
                Colorizer.WriteLine("[Green!Request UserNameToken Nonce value is valid BASE64 string]");
            }


            return true;
        }

        /// <summary>
        /// Mains the specified arguments.
        /// </summary>
        /// <param name="args">The arguments.</param>
        static void Main(string[] args)
        {
            if (!Parser.TryParse(args, out Options options))
            {
                return;
            }

            var file = new FileInfo(options.Source);
            if (!file.Exists)
            {
                Colorizer.WriteLine("[Red!Source does not exist : {0}]",options.Source);
                Colorizer.WriteLine("[White!Hit Enter to Continue]");
                Console.ReadLine();
                return;
            }


            //We have our inputs lets work with them

            //Extract the information from the XML
            var originalRequest = GetRequest(options.Source);
            bool isValidRequest = ValidateRequest(originalRequest);

            if (isValidRequest)
            {
                Colorizer.WriteLine("[White!Recalculating PasswordDigest]");
                byte[] newDigest = CalculateDigest(originalRequest, options.Password);
                string base64Digest = Convert.ToBase64String(newDigest);

                Colorizer.WriteLine("[White!Comparing PasswordDigest]");

                if (newDigest.SequenceEqual(originalRequest.userNameToken.PasswordBytes)) {
                    Colorizer.WriteLine("[Green!PasswordDigest Matches]");

                } else
                {
                    Colorizer.WriteLine("[Red!PasswordDigest Do Not Match]");
                    Colorizer.WriteLine("[Red!Original Digest As Hex String. Value: {0}]", BitConverter.ToString(originalRequest.userNameToken.PasswordBytes).Replace(" - ", " ").ToLowerInvariant());
                    Colorizer.WriteLine("[Red!Recalculated Digest As Hex String. Value: {0}]", BitConverter.ToString(newDigest).Replace(" - ", " ").ToLowerInvariant());
                    Colorizer.WriteLine("[Red!Original Digest As BASE64 String. Value: {0}]", originalRequest.userNameToken.Password);
                    Colorizer.WriteLine("[Red!Recalculated Digest As BASE64 String. Value: {0}]", base64Digest);
                }

            }

            Colorizer.WriteLine("[White!Hit Enter to Continue]");
            Console.ReadLine();
        }
    }
}
