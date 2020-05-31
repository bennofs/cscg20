using System;
using System.Linq;
using dnlib.DotNet;
using System.Reflection;

namespace cscg {
	public class Program {
		public static void Main(string[] args) {
			// Load ReMe.dll
			var mod = ModuleDefMD.Load(args[0]);

			var programCls = mod.GetTypes().First(type => type.Name == "Program");
			var initialCheckMet = programCls.Methods.First(m => m.Name == "InitialCheck");
			var offset = (uint)mod.Metadata.PEImage.ToFileOffset(initialCheckMet.RVA);
			Console.WriteLine(initialCheckMet.Body.CodeStartOffset);
			Console.WriteLine(initialCheckMet.Body.CodeEndOffset);
		}
	}
}
