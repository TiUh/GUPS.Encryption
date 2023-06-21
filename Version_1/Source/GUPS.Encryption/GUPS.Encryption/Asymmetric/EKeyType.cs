using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GUPS.Encryption.Asymmetric
{
    /// <summary>
    /// This enum is used to specify the type of the key blob.
    /// </summary>
    public enum EKeyType
    {
        /// <summary>
        /// The blob contains the public key.
        /// </summary>
        PUBLIC,

        /// <summary>
        /// The blob contains the private key.
        /// </summary>
        PRIVATE,
    }
}
