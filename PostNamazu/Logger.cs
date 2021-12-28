using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PostNamazu
{
    public class Logger
    {
        private static Action<string> logger;

        public static void SetLogger(Action<string> logger)
        {
            Logger.logger = logger;
        }

        public static void Log(string str)
        {
            if (logger != null)
            {
                logger(str);
            }
        }
    }
}
