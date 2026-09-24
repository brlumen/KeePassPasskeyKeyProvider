using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Resources;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// ResourceManager that takes culture resources ({baseName}.{culture}.resources) from the main assembly instead of
	/// satellite assemblies: the plugin ships as a single DLL. Missing cultures and strings fall back to the neutral resources.
	/// </summary>
	internal sealed class EmbeddedResourceManager : ResourceManager
	{
		private readonly Dictionary<string, ResourceSet> cultureSets = new Dictionary<string, ResourceSet>();

		public EmbeddedResourceManager(string baseName, Assembly assembly) : base(baseName, assembly)
		{
		}

		protected override ResourceSet InternalGetResourceSet(CultureInfo culture, bool createIfNotExists, bool tryParents)
		{
			if (culture.Equals(CultureInfo.InvariantCulture))
				return base.InternalGetResourceSet(culture, createIfNotExists, tryParents);

			ResourceSet set;
			lock (cultureSets)
			{
				if (!cultureSets.TryGetValue(culture.Name, out set))
				{
					Stream stream = MainAssembly.GetManifestResourceStream($"{BaseName}.{culture.Name}.resources");
					set = stream == null ? null : new ResourceSet(stream);
					cultureSets.Add(culture.Name, set);
				}
			}

			return set ?? (tryParents ? base.InternalGetResourceSet(CultureInfo.InvariantCulture, createIfNotExists, true) : null);
		}
	}
}
