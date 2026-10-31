// language: C#, file: Program.cs, target: net48 x64
using System;
using System.Windows.Forms;

namespace FFAim
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}