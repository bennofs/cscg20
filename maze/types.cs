/*
 * Generated code file by Il2CppInspector - http://www.djkaty.com - https://github.com/djkaty
 */

using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Cinemachine;
using Cinemachine.Utility;
using Lightbug.CharacterControllerPro.Core;
using Lightbug.CharacterControllerPro.Implementation;
using Lightbug.Utilities;
using TMPro;
using UnityEngine;
using UnityEngine.AI;
using UnityEngine.Events;
using UnityEngine.EventSystems;
using UnityEngine.Networking;
using UnityEngine.Playables;
using UnityEngine.Rendering;
using UnityEngine.Rendering.PostProcessing;
using UnityEngine.SceneManagement;
using UnityEngine.Serialization;
using UnityEngine.TextCore;
using UnityEngine.TextCore.LowLevel;
using UnityEngine.Timeline;
using UnityEngine.UI;
using VisualDesignCafe.Pooling;
using VisualDesignCafe.Rendering;

// Image 0: mscorlib.dll - Assembly: mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 - Types 0-1117
[assembly: Guid] // 0x0022BD10-0x0022BDD0
[assembly: InternalsVisibleTo] // 0x0022BD10-0x0022BDD0
[assembly: InternalsVisibleTo] // 0x0022BD10-0x0022BDD0
[assembly: InternalsVisibleTo] // 0x0022BD10-0x0022BDD0
[assembly: InternalsVisibleTo] // 0x0022BD10-0x0022BDD0
[assembly: InternalsVisibleTo] // 0x0022BD10-0x0022BDD0

// Image 1: System.dll - Assembly: System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e - Types 1118-1224
[assembly: InternalsVisibleTo] // 0x0022BF30-0x0022BFB0
[assembly: InternalsVisibleTo] // 0x0022BF30-0x0022BFB0
[assembly: InternalsVisibleTo] // 0x0022BF30-0x0022BFB0
[assembly: InternalsVisibleTo] // 0x0022BF30-0x0022BFB0

// Image 2: System.Core.dll - Assembly: System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=7cec85d7bea7798e - Types 1225-1248
// Image 3: UnityEngine.SharedInternalsModule.dll - Assembly: UnityEngine.SharedInternalsModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1249-1253
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: InternalsVisibleTo] // 0x0022C120-0x0022D190
[assembly: UnityEngineModuleAssembly] // 0x0022C120-0x0022D190

// Image 4: UnityEngine.CoreModule.dll - Assembly: UnityEngine.CoreModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1254-1799
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: InternalsVisibleTo] // 0x0022FAE0-0x00230B60
[assembly: UnityEngineModuleAssembly] // 0x0022FAE0-0x00230B60

// Image 5: UnityEngine.InputLegacyModule.dll - Assembly: UnityEngine.InputLegacyModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1800-1808
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: InternalsVisibleTo] // 0x00230B80-0x00231BE0
[assembly: UnityEngineModuleAssembly] // 0x00230B80-0x00231BE0

// Image 6: UnityEngine.PhysicsModule.dll - Assembly: UnityEngine.PhysicsModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1809-1829
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: InternalsVisibleTo] // 0x00231D10-0x00232D70
[assembly: UnityEngineModuleAssembly] // 0x00231D10-0x00232D70

// Image 7: UnityEngine.SubsystemsModule.dll - Assembly: UnityEngine.SubsystemsModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1830-1841
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: InternalsVisibleTo] // 0x00232E60-0x00233EC0
[assembly: UnityEngineModuleAssembly] // 0x00232E60-0x00233EC0

// Image 8: UnityEngine.TextRenderingModule.dll - Assembly: UnityEngine.TextRenderingModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1842-1854
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: InternalsVisibleTo] // 0x00233F20-0x00234F80
[assembly: UnityEngineModuleAssembly] // 0x00233F20-0x00234F80

// Image 9: UnityEngine.AudioModule.dll - Assembly: UnityEngine.AudioModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1855-1868
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: InternalsVisibleTo] // 0x00235080-0x00236140
[assembly: UnityEngineModuleAssembly] // 0x00235080-0x00236140

// Image 10: UnityEngine.GridModule.dll - Assembly: UnityEngine.GridModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1869-1870
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: InternalsVisibleTo] // 0x00236190-0x002371F0
[assembly: UnityEngineModuleAssembly] // 0x00236190-0x002371F0

// Image 11: UnityEngine.IMGUIModule.dll - Assembly: UnityEngine.IMGUIModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1871-1907
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: InternalsVisibleTo] // 0x002376F0-0x00238770
[assembly: UnityEngineModuleAssembly] // 0x002376F0-0x00238770

// Image 12: UnityEngine.Physics2DModule.dll - Assembly: UnityEngine.Physics2DModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1908-1927
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: InternalsVisibleTo] // 0x002388E0-0x00239940
[assembly: UnityEngineModuleAssembly] // 0x002388E0-0x00239940

// Image 13: UnityEngine.TerrainModule.dll - Assembly: UnityEngine.TerrainModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1928-1946
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: InternalsVisibleTo] // 0x002399D0-0x0023AA30
[assembly: UnityEngineModuleAssembly] // 0x002399D0-0x0023AA30

// Image 14: UnityEngine.XRModule.dll - Assembly: UnityEngine.XRModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1947-1973
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: InternalsVisibleTo] // 0x0023ABC0-0x0023BC20
[assembly: UnityEngineModuleAssembly] // 0x0023ABC0-0x0023BC20

// Image 15: UnityEngine.AIModule.dll - Assembly: UnityEngine.AIModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1974-1977
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: InternalsVisibleTo] // 0x0023BCB0-0x0023CD10
[assembly: UnityEngineModuleAssembly] // 0x0023BCB0-0x0023CD10

// Image 16: UnityEngine.AndroidJNIModule.dll - Assembly: UnityEngine.AndroidJNIModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1978-1991
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: InternalsVisibleTo] // 0x0023CDE0-0x0023DE40
[assembly: UnityEngineModuleAssembly] // 0x0023CDE0-0x0023DE40

// Image 17: UnityEngine.AnimationModule.dll - Assembly: UnityEngine.AnimationModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 1992-2032
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: InternalsVisibleTo] // 0x0023E130-0x0023F190
[assembly: UnityEngineModuleAssembly] // 0x0023E130-0x0023F190

// Image 18: UnityEngine.AssetBundleModule.dll - Assembly: UnityEngine.AssetBundleModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2033-2036
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: InternalsVisibleTo] // 0x0023F1C0-0x00240240
[assembly: UnityEngineModuleAssembly] // 0x0023F1C0-0x00240240

// Image 19: UnityEngine.DirectorModule.dll - Assembly: UnityEngine.DirectorModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2037-2038
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: InternalsVisibleTo] // 0x00240280-0x002412E0
[assembly: UnityEngineModuleAssembly] // 0x00240280-0x002412E0

// Image 20: UnityEngine.InputModule.dll - Assembly: UnityEngine.InputModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2039-2043
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: InternalsVisibleTo] // 0x00241330-0x002423B0
[assembly: UnityEngineModuleAssembly] // 0x00241330-0x002423B0

// Image 21: UnityEngine.ParticleSystemModule.dll - Assembly: UnityEngine.ParticleSystemModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2044-2054
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: InternalsVisibleTo] // 0x00242580-0x002435E0
[assembly: UnityEngineModuleAssembly] // 0x00242580-0x002435E0

// Image 22: UnityEngine.SpriteShapeModule.dll - Assembly: UnityEngine.SpriteShapeModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2055-2056
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: InternalsVisibleTo] // 0x00243620-0x00244680
[assembly: UnityEngineModuleAssembly] // 0x00243620-0x00244680

// Image 23: UnityEngine.TerrainPhysicsModule.dll - Assembly: UnityEngine.TerrainPhysicsModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2057-2058
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: InternalsVisibleTo] // 0x00244680-0x002456E0
[assembly: UnityEngineModuleAssembly] // 0x00244680-0x002456E0

// Image 24: UnityEngine.TextCoreModule.dll - Assembly: UnityEngine.TextCoreModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2059-2073
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: InternalsVisibleTo] // 0x00245A20-0x00246BA0
[assembly: UnityEngineModuleAssembly] // 0x00245A20-0x00246BA0

// Image 25: UnityEngine.TilemapModule.dll - Assembly: UnityEngine.TilemapModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2074-2083
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: InternalsVisibleTo] // 0x00246D30-0x00247D90
[assembly: UnityEngineModuleAssembly] // 0x00246D30-0x00247D90

// Image 26: UnityEngine.UIElementsNativeModule.dll - Assembly: UnityEngine.UIElementsNativeModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2084-2093
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: InternalsVisibleTo] // 0x00247E50-0x00248EB0
[assembly: UnityEngineModuleAssembly] // 0x00247E50-0x00248EB0

// Image 27: UnityEngine.UIModule.dll - Assembly: UnityEngine.UIModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2094-2104
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: InternalsVisibleTo] // 0x00248F10-0x00249F70
[assembly: UnityEngineModuleAssembly] // 0x00248F10-0x00249F70

// Image 28: UnityEngine.UnityAnalyticsModule.dll - Assembly: UnityEngine.UnityAnalyticsModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2105-2115
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: InternalsVisibleTo] // 0x0024A010-0x0024B070
[assembly: UnityEngineModuleAssembly] // 0x0024A010-0x0024B070

// Image 29: UnityEngine.UnityWebRequestModule.dll - Assembly: UnityEngine.UnityWebRequestModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2116-2128
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: InternalsVisibleTo] // 0x0024B0A0-0x0024C100
[assembly: UnityEngineModuleAssembly] // 0x0024B0A0-0x0024C100

// Image 30: UnityEngine.VFXModule.dll - Assembly: UnityEngine.VFXModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2129-2136
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: InternalsVisibleTo] // 0x0024C1A0-0x0024D280
[assembly: UnityEngineModuleAssembly] // 0x0024C1A0-0x0024D280

// Image 31: UnityEngine.VRModule.dll - Assembly: UnityEngine.VRModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2137-2140
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: InternalsVisibleTo] // 0x0024D290-0x0024E2F0
[assembly: UnityEngineModuleAssembly] // 0x0024D290-0x0024E2F0

// Image 32: UnityEngine.VideoModule.dll - Assembly: UnityEngine.VideoModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2141-2155
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: InternalsVisibleTo] // 0x0024E440-0x0024F500
[assembly: UnityEngineModuleAssembly] // 0x0024E440-0x0024F500

// Image 33: UnityEngine.WindModule.dll - Assembly: UnityEngine.WindModule, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2156-2158
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: InternalsVisibleTo] // 0x0024F500-0x00250560
[assembly: UnityEngineModuleAssembly] // 0x0024F500-0x00250560

// Image 35: VisualDesignCafe.Pooling.dll - Assembly: VisualDesignCafe.Pooling, Version=1.1.8.23, Culture=neutral, PublicKeyToken=null - Types 2160-2168
// Image 36: Unity.Postprocessing.Runtime.dll - Assembly: Unity.Postprocessing.Runtime, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2169-2298
// Image 37: Unity.Timeline.dll - Assembly: Unity.Timeline, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2299-2366
[assembly: Guid] // 0x002515F0-0x00251700
[assembly: InternalsVisibleTo] // 0x002515F0-0x00251700
[assembly: InternalsVisibleTo] // 0x002515F0-0x00251700
[assembly: InternalsVisibleTo] // 0x002515F0-0x00251700
[assembly: InternalsVisibleTo] // 0x002515F0-0x00251700
[assembly: InternalsVisibleTo] // 0x002515F0-0x00251700
[assembly: InternalsVisibleTo] // 0x002515F0-0x00251700
[assembly: InternalsVisibleTo] // 0x002515F0-0x00251700
[assembly: InternalsVisibleTo] // 0x002515F0-0x00251700

// Image 38: UnityEngine.UI.dll - Assembly: UnityEngine.UI, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2367-2548
[assembly: Guid] // 0x00252F90-0x00252FE0
[assembly: InternalsVisibleTo] // 0x00252F90-0x00252FE0

// Image 39: VisualDesignCafe.Rendering.dll - Assembly: VisualDesignCafe.Rendering, Version=1.1.8.23, Culture=neutral, PublicKeyToken=null - Types 2549-2557
// Image 40: Cinemachine.dll - Assembly: Cinemachine, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2558-2713
[assembly: InternalsVisibleTo] // 0x002536D0-0x002536F0

// Image 41: MeshExtension.dll - Assembly: MeshExtension, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2714-2715
[assembly: Guid] // 0x002536F0-0x00253710

// Image 42: Unity.TextMeshPro.dll - Assembly: Unity.TextMeshPro, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2716-2850
[assembly: InternalsVisibleTo] // 0x00254AC0-0x00254B10
[assembly: InternalsVisibleTo] // 0x00254AC0-0x00254B10

// Image 43: VisualDesignCafe.Rendering.Nature.dll - Assembly: VisualDesignCafe.Rendering.Nature, Version=1.1.8.23, Culture=neutral, PublicKeyToken=null - Types 2851-2889
// Image 44: VisualDesignCafe.Nature.dll - Assembly: VisualDesignCafe.Nature, Version=1.2.3.23, Culture=neutral, PublicKeyToken=null - Types 2890-2894
// Image 45: Assembly-CSharp.dll - Assembly: Assembly-CSharp, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null - Types 2895-3200

internal sealed class Locale // TypeDefIndex: 1
{
	// Methods
	public static string GetText(string msg); // 0x006A9090-0x006A90A0
	public static string GetText(string fmt, params /* 0x0022BB10-0x0022BB20 */ object[] args); // 0x006BF7B0-0x006BF7C0
}

internal static class SR // TypeDefIndex: 2
{
	// Methods
	internal static string Format(string resourceFormat, object p1); // 0x0064A250-0x0064A380
	internal static string Format(string resourceFormat, object p1, object p2); // 0x0064A380-0x0064A4C0
}

internal sealed class <PrivateImplementationDetails> // TypeDefIndex: 1075
{
	// Fields
	internal static readonly __StaticArrayInitTypeSize=72 0588059ACBD52F7EA2835882F977A9CF72EB9775; // 0x00
	internal static readonly __StaticArrayInitTypeSize=84 0A1ADB22C1D3E1F4B2448EE3F27DF9DE63329C4C; // 0x48
	internal static readonly __StaticArrayInitTypeSize=240 121EC59E23F7559B28D338D562528F6299C2DE22; // 0x9C
	internal static readonly __StaticArrayInitTypeSize=24 1730F09044E91DB8371B849EFF5E6D17BDE4AED0; // 0x18C
	internal static readonly __StaticArrayInitTypeSize=16 1FE6CE411858B3D864679DE2139FB081F08BFACD; // 0x1A4
	internal static readonly __StaticArrayInitTypeSize=40 25420D0055076FA8D3E4DD96BC53AE24DE6E619F; // 0x1B4
	internal static readonly __StaticArrayInitTypeSize=1208 25CF935D2AE9EDF05DD75BCD47FF84D9255D6F6E; // 0x1DC
	internal static readonly __StaticArrayInitTypeSize=42 29C1A61550F0E3260E1953D4FAD71C256218EF40; // 0x694
	internal static readonly __StaticArrayInitTypeSize=12 2B33BEC8C30DFDC49DAFE20D3BDE19487850D717; // 0x6BE
	internal static readonly __StaticArrayInitTypeSize=36 2BA840FF6020B8FF623DBCB7188248CF853FAF4F; // 0x6CA
	internal static readonly __StaticArrayInitTypeSize=72 2C840AFA48C27B9C05593E468C1232CA1CC74AFD; // 0x6EE
	internal static readonly __StaticArrayInitTypeSize=16 2D1DA5BB407F0C11C3B5116196C0C6374D932B20; // 0x736
	internal static readonly __StaticArrayInitTypeSize=72 2F71D2DA12F3CD0A6A112F5A5A75B4FDC6FE8547; // 0x746
	internal static readonly __StaticArrayInitTypeSize=72 34476C29F6F81C989CFCA42F7C06E84C66236834; // 0x78E
	internal static readonly __StaticArrayInitTypeSize=2382 35EED060772F2748D13B745DAEC8CD7BD3B87604; // 0x7D6
	internal static readonly __StaticArrayInitTypeSize=38 375F9AE9769A3D1DA789E9ACFE81F3A1BB14F0D3; // 0x1124
	internal static readonly __StaticArrayInitTypeSize=1450 379C06C9E702D31469C29033F0DD63931EB349F5; // 0x114A
	internal static readonly __StaticArrayInitTypeSize=72 39C9CE73C7B0619D409EF28344F687C1B5C130FE; // 0x16F4
	internal static readonly __StaticArrayInitTypeSize=320 3C53AFB51FEC23491684C7BEDBC6D4E0F409F851; // 0x173C
	internal static readonly __StaticArrayInitTypeSize=12 3E823444D2DFECF0F90B436B88F02A533CB376F1; // 0x187C
	internal static readonly __StaticArrayInitTypeSize=72 3FE6C283BCF384FD2C8789880DFF59664E2AB4A1; // 0x1888
	internal static readonly __StaticArrayInitTypeSize=1665 40981BAA39513E58B28DCF0103CC04DE2A0A0444; // 0x18D0
	internal static readonly __StaticArrayInitTypeSize=40 40E7C49413D261F3F38AD3A870C0AC69C8BDA048; // 0x1F51
	internal static readonly __StaticArrayInitTypeSize=72 421EC7E82F2967DF6CA8C3605514DC6F29EE5845; // 0x1F79
	internal static readonly __StaticArrayInitTypeSize=256 433175D38B13FFE177FDD661A309F1B528B3F6E2; // 0x1FC1
	internal static readonly __StaticArrayInitTypeSize=72 4858DB4AA76D3933F1CA9E6712D4FDB16903F628; // 0x20C1
	internal static readonly __StaticArrayInitTypeSize=40 4F7A8890F332B22B8DE0BD29D36FA7364748D76A; // 0x2109
	internal static readonly __StaticArrayInitTypeSize=72 536422B321459B242ADED7240B7447E904E083E3; // 0x2131
	internal static readonly __StaticArrayInitTypeSize=1080 5382CEF491F422BFE0D6FC46EFAFF9EF9D4C89F3; // 0x2179
	internal static readonly __StaticArrayInitTypeSize=3 57218C316B6921E2CD61027A2387EDC31A2D9471; // 0x25B1
	internal static readonly __StaticArrayInitTypeSize=40 57F320D62696EC99727E0FE2045A05F1289CC0C6; // 0x25B4
	internal static readonly __StaticArrayInitTypeSize=212 594A33A00BC4F785DFD43E3C6C44FBA1242CCAF3; // 0x25DC
	internal static readonly __StaticArrayInitTypeSize=36 5BBDF8058D4235C33F2E8DCF76004031B6187A2F; // 0x26B0
	internal static readonly __StaticArrayInitTypeSize=288 5BCD21C341BE6DDF8FFFAE1A23ABA24DCBB612BF; // 0x26D4
	internal static readonly __StaticArrayInitTypeSize=72 5BFE2819B4778217C56416C7585FF0E56EBACD89; // 0x27F4
	internal static readonly __StaticArrayInitTypeSize=128 609C0E8D8DA86A09D6013D301C86BA8782C16B8C; // 0x283C
	internal static readonly __StaticArrayInitTypeSize=40 65E32B4E150FD8D24B93B0D42A17F1DAD146162B; // 0x28BC
	internal static readonly __StaticArrayInitTypeSize=52 6770974FEF1E98B9C1864370E2B5B786EB0EA39E; // 0x28E4
	internal static readonly __StaticArrayInitTypeSize=72 67EEAD805D708D9AA4E14BF747E44CED801744F3; // 0x2918
	internal static readonly __StaticArrayInitTypeSize=120 6C71197D228427B2864C69B357FEF73D8C9D59DF; // 0x2960
	internal static readonly __StaticArrayInitTypeSize=16 6CEE45445AFD150B047A5866FFA76AA651CDB7B7; // 0x29D8
	internal static readonly __StaticArrayInitTypeSize=76 6FC754859E4EC74E447048364B216D825C6F8FE7; // 0x29E8
	internal static readonly __StaticArrayInitTypeSize=40 704939CD172085D1295FCE3F1D92431D685D7AA2; // 0x2A34
	internal static readonly __StaticArrayInitTypeSize=24 7088AAE49F0627B72729078DE6E3182DDCF8ED99; // 0x2A5C
	internal static readonly __StaticArrayInitTypeSize=72 7341C933A70EAE383CC50C4B945ADB8E08F06737; // 0x2A74
	internal static readonly __StaticArrayInitTypeSize=40 7FE820C9CF0F0B90445A71F1D262D22E4F0C4C68; // 0x2ABC
	internal static readonly __StaticArrayInitTypeSize=21252 811A927B7DADD378BE60BBDE794B9277AA9B50EC; // 0x2AE4
	internal static readonly __StaticArrayInitTypeSize=36 81917F1E21F3C22B9F916994547A614FB03E968E; // 0x7DE8
	internal static readonly __StaticArrayInitTypeSize=40 823566DA642D6EA356E15585921F2A4CA23D6760; // 0x7E0C
	internal static readonly __StaticArrayInitTypeSize=12 82C2A59850B2E85BCE1A45A479537A384DF6098D; // 0x7E34
	internal static readonly __StaticArrayInitTypeSize=44 82C383F8E6E4D3D87AEBB986A5D0077E8AD157C4; // 0x7E40
	internal static readonly __StaticArrayInitTypeSize=40 871B9CF85DB352BAADF12BAE8F19857683E385AC; // 0x7E6C
	internal static readonly __StaticArrayInitTypeSize=16 89A040451C8CC5C8FB268BE44BDD74964C104155; // 0x7E94
	internal static readonly __StaticArrayInitTypeSize=40 8CAA092E783257106251246FF5C97F88D28517A6; // 0x7EA4
	internal static readonly __StaticArrayInitTypeSize=2100 8D231DD55FE1AD7631BBD0905A17D5EB616C2154; // 0x7ECC
	internal static readonly __StaticArrayInitTypeSize=40 8E10AC2F34545DFBBF3FCBC06055D797A8C99991; // 0x8700
	internal static readonly __StaticArrayInitTypeSize=12 93A63E90605400F34B49F0EB3361D23C89164BDA; // 0x8728
	internal static readonly __StaticArrayInitTypeSize=72 94841DD2F330CCB1089BF413E4FA9B04505152E2; // 0x8734
	internal static readonly __StaticArrayInitTypeSize=12 95264589E48F94B7857CFF398FB72A537E13EEE2; // 0x877C
	internal static readonly __StaticArrayInitTypeSize=72 95C48758CAE1715783472FB073AB158AB8A0AB2A; // 0x8788
	internal static readonly __StaticArrayInitTypeSize=72 973417296623D8DC6961B09664E54039E44CA5D8; // 0x87D0
	internal static readonly __StaticArrayInitTypeSize=40 A0074C15377C0C870B055927403EA9FA7A349D12; // 0x8818
	internal static readonly __StaticArrayInitTypeSize=130 A1319B706116AB2C6D44483F60A7D0ACEA543396; // 0x8840
	internal static readonly long A13AA52274D951A18029131A8DDECF76B569A15D; // 0x88C8
	internal static readonly __StaticArrayInitTypeSize=212 A5444763673307F6828C748D4B9708CFC02B0959; // 0x88D0
	internal static readonly __StaticArrayInitTypeSize=72 A6732F8E7FC23766AB329B492D6BF82E3B33233F; // 0x89A4
	internal static readonly __StaticArrayInitTypeSize=174 A705A106D95282BD15E13EEA6B0AF583FF786D83; // 0x89EC
	internal static readonly __StaticArrayInitTypeSize=1018 A8A491E4CED49AE0027560476C10D933CE70C8DF; // 0x8A9A
	internal static readonly __StaticArrayInitTypeSize=72 AC791C4F39504D1184B73478943D0636258DA7B1; // 0x8E94
	internal static readonly __StaticArrayInitTypeSize=52 AFCD4E1211233E99373A3367B23105A3D624B1F2; // 0x8EDC
	internal static readonly __StaticArrayInitTypeSize=40 B472ED77CB3B2A66D49D179F1EE2081B70A6AB61; // 0x8F10
	internal static readonly __StaticArrayInitTypeSize=256 B53A2C6DF21FC88B17AEFC40EB895B8D63210CDF; // 0x8F38
	internal static readonly __StaticArrayInitTypeSize=998 B881DA88BE0B68D8A6B6B6893822586B8B2CFC45; // 0x9038
	internal static readonly __StaticArrayInitTypeSize=162 B8864ACB9DD69E3D42151513C840AAE270BF21C8; // 0x941E
	internal static readonly __StaticArrayInitTypeSize=360 B8F87834C3597B2EEF22BA6D3A392CC925636401; // 0x94C0
	internal static readonly __StaticArrayInitTypeSize=72 B9B670F134A59FB1107AF01A9FE8F8E3980B3093; // 0x9628
	internal static readonly __StaticArrayInitTypeSize=72 BEBC9ECC660A13EFC359BA3383411F698CFF25DB; // 0x9670
	internal static readonly __StaticArrayInitTypeSize=40 BEE1CFE5DFAA408E14CE4AF4DCD824FA2E42DCB7; // 0x96B8
	internal static readonly long C1A1100642BA9685B30A84D97348484E14AA1865; // 0x96E0
	internal static readonly __StaticArrayInitTypeSize=16 C6F364A0AD934EFED8909446C215752E565D77C1; // 0x96E8
	internal static readonly __StaticArrayInitTypeSize=174 CE5835130F5277F63D716FC9115526B0AC68FFAD; // 0x96F8
	internal static readonly __StaticArrayInitTypeSize=32 D117188BE8D4609C0D531C51B0BB911A4219DEBE; // 0x97A6
	internal static readonly __StaticArrayInitTypeSize=44 D78D08081C7A5AD6FBA7A8DC86BCD6D7A577C636; // 0x97C6
	internal static readonly __StaticArrayInitTypeSize=76 DA19DB47B583EFCF7825D2E39D661D2354F28219; // 0x97F2
	internal static readonly __StaticArrayInitTypeSize=52 DD3AEFEADB1CD615F3017763F1568179FEE640B0; // 0x983E
	internal static readonly __StaticArrayInitTypeSize=36 E1827270A5FE1C85F5352A66FD87BA747213D006; // 0x9872
	internal static readonly __StaticArrayInitTypeSize=40 E45BAB43F7D5D038672B3E3431F92E34A7AF2571; // 0x9896
	internal static readonly __StaticArrayInitTypeSize=52 E92B39D8233061927D9ACDE54665E68E7535635A; // 0x98BE
	internal static readonly __StaticArrayInitTypeSize=12 EA9506959484C55CFE0C139C624DF6060E285866; // 0x98F2
	internal static readonly __StaticArrayInitTypeSize=262 EB5E9A80A40096AB74D2E226650C7258D7BC5E9D; // 0x98FE
	internal static readonly __StaticArrayInitTypeSize=64 EBF68F411848D603D059DFDEA2321C5A5EA78044; // 0x9A04
	internal static readonly __StaticArrayInitTypeSize=72 EC89C317EA2BF49A70EFF5E89C691E34733D7C37; // 0x9A44
	internal static readonly __StaticArrayInitTypeSize=40 F06E829E62F3AFBC045D064E10A4F5DF7C969612; // 0x9A8C
	internal static readonly __StaticArrayInitTypeSize=11614 F073AA332018FDA0D572E99448FFF1D6422BD520; // 0x9AB4
	internal static readonly __StaticArrayInitTypeSize=120 F34B0E10653402E8F788F8BC3F7CD7090928A429; // 0xC812
	internal static readonly __StaticArrayInitTypeSize=72 F37E34BEADB04F34FCC31078A59F49856CA83D5B; // 0xC88A
	internal static readonly __StaticArrayInitTypeSize=94 F512A9ABF88066AAEB92684F95CC05D8101B462B; // 0xC8D2
	internal static readonly __StaticArrayInitTypeSize=12 F8FAABB821300AA500C2CEC6091B3782A7FB44A4; // 0xC930
	internal static readonly __StaticArrayInitTypeSize=2350 FCBD2781A933F0828ED4AAF88FD8B08D76DDD49B; // 0xC93C

	// Nested types
	private struct __StaticArrayInitTypeSize=3 // TypeDefIndex: 1076
	{
	}

	private struct __StaticArrayInitTypeSize=12 // TypeDefIndex: 1077
	{
	}

	private struct __StaticArrayInitTypeSize=16 // TypeDefIndex: 1078
	{
	}

	private struct __StaticArrayInitTypeSize=24 // TypeDefIndex: 1079
	{
	}

	private struct __StaticArrayInitTypeSize=32 // TypeDefIndex: 1080
	{
	}

	private struct __StaticArrayInitTypeSize=36 // TypeDefIndex: 1081
	{
	}

	private struct __StaticArrayInitTypeSize=38 // TypeDefIndex: 1082
	{
	}

	private struct __StaticArrayInitTypeSize=40 // TypeDefIndex: 1083
	{
	}

	private struct __StaticArrayInitTypeSize=42 // TypeDefIndex: 1084
	{
	}

	private struct __StaticArrayInitTypeSize=44 // TypeDefIndex: 1085
	{
	}

	private struct __StaticArrayInitTypeSize=52 // TypeDefIndex: 1086
	{
	}

	private struct __StaticArrayInitTypeSize=64 // TypeDefIndex: 1087
	{
	}

	private struct __StaticArrayInitTypeSize=72 // TypeDefIndex: 1088
	{
	}

	private struct __StaticArrayInitTypeSize=76 // TypeDefIndex: 1089
	{
	}

	private struct __StaticArrayInitTypeSize=84 // TypeDefIndex: 1090
	{
	}

	private struct __StaticArrayInitTypeSize=94 // TypeDefIndex: 1091
	{
	}

	private struct __StaticArrayInitTypeSize=120 // TypeDefIndex: 1092
	{
	}

	private struct __StaticArrayInitTypeSize=128 // TypeDefIndex: 1093
	{
	}

	private struct __StaticArrayInitTypeSize=130 // TypeDefIndex: 1094
	{
	}

	private struct __StaticArrayInitTypeSize=162 // TypeDefIndex: 1095
	{
	}

	private struct __StaticArrayInitTypeSize=174 // TypeDefIndex: 1096
	{
	}

	private struct __StaticArrayInitTypeSize=212 // TypeDefIndex: 1097
	{
	}

	private struct __StaticArrayInitTypeSize=240 // TypeDefIndex: 1098
	{
	}

	private struct __StaticArrayInitTypeSize=256 // TypeDefIndex: 1099
	{
	}

	private struct __StaticArrayInitTypeSize=262 // TypeDefIndex: 1100
	{
	}

	private struct __StaticArrayInitTypeSize=288 // TypeDefIndex: 1101
	{
	}

	private struct __StaticArrayInitTypeSize=320 // TypeDefIndex: 1102
	{
	}

	private struct __StaticArrayInitTypeSize=360 // TypeDefIndex: 1103
	{
	}

	private struct __StaticArrayInitTypeSize=998 // TypeDefIndex: 1104
	{
	}

	private struct __StaticArrayInitTypeSize=1018 // TypeDefIndex: 1105
	{
	}

	private struct __StaticArrayInitTypeSize=1080 // TypeDefIndex: 1106
	{
	}

	private struct __StaticArrayInitTypeSize=1208 // TypeDefIndex: 1107
	{
	}

	private struct __StaticArrayInitTypeSize=1450 // TypeDefIndex: 1108
	{
	}

	private struct __StaticArrayInitTypeSize=1665 // TypeDefIndex: 1109
	{
	}

	private struct __StaticArrayInitTypeSize=2100 // TypeDefIndex: 1110
	{
	}

	private struct __StaticArrayInitTypeSize=2350 // TypeDefIndex: 1111
	{
	}

	private struct __StaticArrayInitTypeSize=2382 // TypeDefIndex: 1112
	{
	}

	private struct __StaticArrayInitTypeSize=11614 // TypeDefIndex: 1113
	{
	}

	private struct __StaticArrayInitTypeSize=21252 // TypeDefIndex: 1114
	{
	}

	// Methods
	internal static uint ComputeStringHash(string s); // 0x005ADE60-0x005ADF10
}

internal static class SR // TypeDefIndex: 1119
{
	// Methods
	internal static string GetString(string name, params /* 0x0022BED0-0x0022BEE0 */ object[] args); // 0x00889740-0x008897F0
	internal static string GetString(CultureInfo culture, string name, params /* 0x0022BEE0-0x0022BEF0 */ object[] args); // 0x008899A0-0x008899B0
	internal static string GetString(string name); // 0x008899B0-0x008899C0
}

internal sealed class <PrivateImplementationDetails> // TypeDefIndex: 1220
{
	// Fields
	internal static readonly long 03F4297FCC30D0FD5E420E5D26E7FA711167C7EF; // 0x00
	internal static readonly __StaticArrayInitTypeSize=32 59F5BD34B6C013DEACC784F69C67E95150033A84; // 0x08
	internal static readonly __StaticArrayInitTypeSize=44 8E0EF3D67A3EB1863224EE3CACB424BC2F8CFBA3; // 0x28
	internal static readonly __StaticArrayInitTypeSize=32 C02C28AFEBE998F767E4AF43E3BE8F5E9FA11536; // 0x54
	internal static readonly __StaticArrayInitTypeSize=128 CCEEADA43268372341F81AE0C9208C6856441C04; // 0x74
	internal static readonly long E5BC1BAFADE1862DD6E0B9FB632BFAA6C3873A78; // 0xF8

	// Nested types
	private struct __StaticArrayInitTypeSize=32 // TypeDefIndex: 1221
	{
	}

	private struct __StaticArrayInitTypeSize=44 // TypeDefIndex: 1222
	{
	}

	private struct __StaticArrayInitTypeSize=128 // TypeDefIndex: 1223
	{
	}
}

internal sealed class <PrivateImplementationDetails> // TypeDefIndex: 1907
{
	// Methods
	internal static uint ComputeStringHash(string s); // 0x0093D950-0x0093DA00
}

namespace VisualDesignCafe.Pooling
{
	public static class ArrayExtensions // TypeDefIndex: 2161
	{
		// Methods
		public static void Resize<T>(ref T[] array, int size, ArrayPool pool)
			where T : struct;
		public static void Copy<T>(T[] source, int sourceOffset, T[] destination, int destinationOffset, int count)
			where T : struct;
		private static void CopyToFast<T>(T[] source, int sourceOffset, T[] destination, int destinationOffset, int count)
			where T : struct;
	}

	public class ArrayPool // TypeDefIndex: 2162
	{
		// Fields
		public static readonly ArrayPool Shared; // 0x00
		private Dictionary<Type, List<PooledArray>> _pool; // 0x10

		// Nested types
		private struct PooledArray // TypeDefIndex: 2163
		{
			// Fields
			public object Array; // 0x00
			public int Length; // 0x08
		}

		// Constructors
		public ArrayPool(); // 0x00B20350-0x00B203C0
		static ArrayPool(); // 0x00B203C0-0x00B20460

		// Methods
		public T[] Alloc<T>(int size, bool clear, bool exact = false /* Metadata: 0x0015A11E */)
			where T : struct;
		public void Free<T>(T[] array)
			where T : struct;
	}

	public class GroupedList<T> : IDisposable // TypeDefIndex: 2164
		where T : struct
	{
		// Fields
		private const int _minFragmentSize = 100; // Metadata: 0x0015A120
		private bool <IsFragmented>k__BackingField;
		private int <Count>k__BackingField;
		private int <FragmentedCount>k__BackingField;
		private int <GroupCount>k__BackingField;
		private readonly PooledList<GroupData> _groups;
		private readonly PooledList<GroupData> _removedGroups;
		private readonly PooledList<SortedGroupData> _sortedGroups;
		private readonly bool _allowFragmentation;
		private readonly Comparer<SortedGroupData> _comparer;
		private T[] _data;

		// Properties
		public bool IsFragmented { get; private set; }
		public int Count { get; private set; }
		protected int AppliedCount { get; }
		protected int FragmentedCount { get; private set; }
		public int GroupCount { get; private set; }
		public T[] Buffer { get; }

		// Nested types
		private struct SortedGroupData : IComparable<SortedGroupData> // TypeDefIndex: 2165
		{
			// Fields
			public int Index;
			public int StartIndex;
			public int Length;

			// Constructors
			public SortedGroupData(SortedGroupData<T> other);
			public SortedGroupData(int index, GroupData<T> group);

			// Methods
			public int CompareTo(SortedGroupData<T> other);
		}

		private struct GroupData // TypeDefIndex: 2166
		{
			// Fields
			public int StartIndex;
			public int Length;

			// Constructors
			public GroupData(int startIndex, int length);
			public GroupData(GroupData<T> other);
		}

		// Constructors
		public GroupedList(int capacity, bool allowFragmentation = false /* Metadata: 0x0015A11F */);

		// Methods
		public void Dispose();
		public void Defragment();
		private int FindNextSlice(PooledList<SortedGroupData> groups, int startIndex);
		public int Add(T[] group, int offset, int length);
		public void Remove(int groupIndex);
		private int FindStartIndex(int length);
	}

	public class PooledList<T> : IDisposable, IEnumerable<T>, IEnumerable // TypeDefIndex: 2167
		where T : struct
	{
		// Fields
		private int <Count>k__BackingField;
		private T[] _buffer;
		private readonly ArrayPool _pool;

		// Properties
		public int Count { get; private set; }
		public T this[int index] { get => default; set {} }

		// Nested types
		private sealed class <GetEnumerator>d__16 : IEnumerator<T>, IEnumerator, IDisposable // TypeDefIndex: 2168
		{
			// Fields
			private int <>1__state;
			private T <>2__current;
			public PooledList<T> <>4__this;
			private int <i>5__2;

			// Properties
			T IEnumerator<T>.Current { [DebuggerHidden] /* 0x002505C0-0x002505D0 */ get; }
			object IEnumerator.Current { [DebuggerHidden] /* 0x002505D0-0x002505E0 */ get; }

			// Constructors
			[DebuggerHidden] // 0x002505A0-0x002505B0
			public <GetEnumerator>d__16(int <>1__state);

			// Methods
			[DebuggerHidden] // 0x002505B0-0x002505C0
			void IDisposable.Dispose();
			private bool MoveNext();
		}

		// Constructors
		public PooledList(int capacity);
		public PooledList(int capacity, ArrayPool pool);

		// Methods
		public void Add(T value);
		public void Clear();
		public void Dispose();
		public void Sort(IComparer<T> comparer);
		public IEnumerator<T> GetEnumerator();
		IEnumerator IEnumerable.GetEnumerator();
	}
}

internal sealed class <PrivateImplementationDetails> // TypeDefIndex: 2297
{
	// Fields
	internal static readonly __StaticArrayInitTypeSize=20 0ED907628EE272F93737B500A23D77C9B1C88368; // 0x00

	// Nested types
	private struct __StaticArrayInitTypeSize=20 // TypeDefIndex: 2298
	{
	}
}

internal sealed class <PrivateImplementationDetails> // TypeDefIndex: 2547
{
	// Fields
	internal static readonly __StaticArrayInitTypeSize=12 7BBE37982E6C057ED87163CAFC7FD6E5E42EEA46; // 0x00

	// Nested types
	private struct __StaticArrayInitTypeSize=12 // TypeDefIndex: 2548
	{
	}
}

namespace VisualDesignCafe.Rendering
{
	public class DynamicBatcher : IEnumerable<InstanceBuffer>, IEnumerable, IDisposable // TypeDefIndex: 2550
	{
		// Fields
		private readonly int _batchSize; // 0x10
		private readonly List<InstanceBuffer> _buffers; // 0x18

		// Constructors
		public DynamicBatcher(); // 0x00AE3180-0x00AE31E0

		// Methods
		public void Dispose(); // 0x00AE19E0-0x00AE1B50
		public int Add(InstanceBufferSlice buffer, ref List<InstanceBuffer> addedBuffers); // 0x00AE1BC0-0x00AE1BF0
		private int Add(InstanceBufferSlice bufferSlice, ref List<InstanceBuffer> addedBuffers, int sliceIndexOffset); // 0x00AE1BF0-0x00AE21F0
		public void Remove(InstanceBuffer buffer); // 0x00AE2A60-0x00AE2EE0
		public IEnumerator<InstanceBuffer> GetEnumerator(); // 0x00AE30A0-0x00AE3110
		IEnumerator IEnumerable.GetEnumerator(); // 0x00AE3110-0x00AE3180
	}

	public struct InstanceBufferSlice // TypeDefIndex: 2551
	{
		// Fields
		public readonly Matrix4x4[] Instances; // 0x00
		public readonly Vector4[] Colors; // 0x08
		public readonly int Offset; // 0x10
		public readonly int Count; // 0x14
		public readonly Bounds Bounds; // 0x18

		// Constructors
		public InstanceBufferSlice(Matrix4x4[] instances, Vector4[] colors, int offset, int count, Bounds bounds); // 0x002838B0-0x002838E0

		// Methods
		public InstanceBufferSlice Slice(int offset, int count, bool absoluteOffset); // 0x002838E0-0x002839A0
	}

	public class InstanceBuffer // TypeDefIndex: 2552
	{
		// Fields
		public readonly Matrix4x4[] Instances; // 0x10
		public readonly Vector4[] Colors; // 0x18
		public readonly int OffsetSelf; // 0x20
		public readonly int CountSelf; // 0x24
		public readonly Bounds Bounds; // 0x28
		private InstanceBuffer <MergedBuffer>k__BackingField; // 0x40
		private int? <IndexInMergedBuffer>k__BackingField; // 0x48
		private bool <IsMerged>k__BackingField; // 0x50
		private GroupedList<Matrix4x4> <MergedInstances>k__BackingField; // 0x58
		private GroupedList<Vector4> <MergedColors>k__BackingField; // 0x60
		private bool <PropertiesAreDirty>k__BackingField; // 0x68
		private MaterialPropertyBlock <Properties>k__BackingField; // 0x70
		private bool <IsDisposed>k__BackingField; // 0x78
		internal float[] Hue; // 0x80
		internal float[] Saturation; // 0x88
		internal float[] Lightness; // 0x90

		// Properties
		public InstanceBuffer MergedBuffer { get; private set; } // 0x00AE31E0-0x00AE31F0 0x00AE31F0-0x00AE3200
		public int? IndexInMergedBuffer { get; internal set; } // 0x00AE3200-0x00AE3210 0x00AE3210-0x00AE3220
		public bool IsMerged { get; private set; } // 0x00AE3220-0x00AE3230 0x00AE3230-0x00AE3240
		public GroupedList<Matrix4x4> MergedInstances { get; private set; } // 0x00AE3240-0x00AE3250 0x00AE3250-0x00AE3260
		public GroupedList<Vector4> MergedColors { get; private set; } // 0x00AE3260-0x00AE3270 0x00AE3270-0x00AE3280
		public bool PropertiesAreDirty { get; set; } // 0x00AE3280-0x00AE3290 0x00AE3290-0x00AE32A0
		public MaterialPropertyBlock Properties { get; internal set; } // 0x00AE32A0-0x00AE32B0 0x00AE32B0-0x00AE32C0
		internal bool IsDisposed { get; private set; } // 0x00AE32C0-0x00AE32D0 0x00AE32D0-0x00AE32E0

		// Constructors
		public InstanceBuffer(); // 0x00AE32E0-0x00AE32F0
		public InstanceBuffer(InstanceBufferSlice slice); // 0x00AE2A10-0x00AE2A60

		// Methods
		public override int GetHashCode(); // 0x00AE32F0-0x00AE3380
		public void Dispose(); // 0x00AE1B50-0x00AE1BC0
		public void Merge(InstanceBuffer destination); // 0x00AE21F0-0x00AE2840
		public void ConvertToMergedBuffer(bool forceColorsAllocation = false /* Metadata: 0x0015A782 */); // 0x00AE2840-0x00AE2A10
		public void Split(); // 0x00AE2EE0-0x00AE30A0
	}

	public struct InstanceData // TypeDefIndex: 2553
	{
		// Fields
		public readonly Mesh Mesh; // 0x00
		public readonly Material[] Materials; // 0x08
		public readonly float CullDistance; // 0x10
		public readonly float SqrCullDistance; // 0x14
		public readonly ShadowCastingMode ShadowCasting; // 0x18
		public readonly bool ReceiveShadow; // 0x1C
		public readonly Bounds Bounds; // 0x20
		public readonly LODFadeMode FadeMode; // 0x38
		public readonly ColorType Color; // 0x3C
		public readonly int Layer; // 0x40
		public readonly bool IsLastLod; // 0x44
		public readonly bool LightProbes; // 0x45
		public readonly bool OcclusionProbes; // 0x46

		// Properties
		public bool IsValid { get; } // 0x002839A0-0x002839C0

		// Nested types
		public enum ColorType // TypeDefIndex: 2554
		{
			None = 0,
			Color = 1,
			Tint = 2,
			HSV = 3
		}

		// Constructors
		public InstanceData(Mesh mesh, Material[] materials, Bounds bounds, float distance, ShadowCastingMode shadowCasting, bool receiveShadows, LODFadeMode fadeMode, ColorType color, int layer, bool isLastLod, bool lightProbes, bool occlusionProbes); // 0x002839C0-0x00283A20
	}

	public class InstanceIndirectRenderer : InstanceRenderer // TypeDefIndex: 2555
	{
		// Fields
		private static Matrix4x4[] _temporaryInstancesBuffer; // 0x00
		private ComputeBuffer _argBuffer; // 0x88
		private ComputeBuffer _positionBuffer; // 0x90
		private MaterialPropertyBlock _properties; // 0x98
		private uint[] _args; // 0xA0
		private Bounds _bounds; // 0xA8
		private object _lock; // 0xC0
		private InstanceBuffer _renderBuffer; // 0xC8
		private bool _cacheIsDirty; // 0xD0

		// Constructors
		public InstanceIndirectRenderer(InstanceData source, bool isHdrp); // 0x00AE3380-0x00AE3440
		static InstanceIndirectRenderer(); // 0x00AE5200-0x00AE5240

		// Methods
		public override void Dispose(); // 0x00AE3550-0x00AE36A0
		public override void FinalizeFrame(); // 0x00AE3BD0-0x00AE3D10
		public override int Add(InstanceBufferSlice buffer, ref List<InstanceBuffer> addedBuffers); // 0x00AE3D10-0x00AE3F40
		public override void Remove(InstanceBuffer buffer); // 0x00AE3F40-0x00AE4260
		public override void Render(Camera camera, Plane[] planes, float cullDistance, bool useCache, out int instancesRendered, out int instancesCulled, out int batchesRendered); // 0x00AE4260-0x00AE4FF0
		private ComputeBuffer GetArgBuffer(); // 0x00AE5170-0x00AE5200
		private ComputeBuffer GetInstancesBuffer(int bufferSize); // 0x00AE4FF0-0x00AE50D0
		private MaterialPropertyBlock GetPropertyBlock(); // 0x00AE50D0-0x00AE5170
		private void DisposeComputeBuffers(); // 0x00AE3B90-0x00AE3BD0
	}

	public class InstanceRenderer // TypeDefIndex: 2556
	{
		// Fields
		private const int _batchSize = 1023; // Metadata: 0x0015A793
		private EventHandler<InstanceRenderer> Disposed; // 0x10
		private EventHandler<AddBufferEventArgs> AddBuffer; // 0x18
		private EventHandler<InstanceBuffer> AddedBuffer; // 0x20
		private EventHandler<InstanceBuffer> RemoveBuffer; // 0x28
		private EventHandler<InstanceBuffer> RemovedBuffer; // 0x30
		public readonly InstanceData Source; // 0x38
		private DynamicBatcher _dynamicBatcher; // 0x80

		// Nested types
		public class AddBufferEventArgs // TypeDefIndex: 2557
		{
			// Fields
			public InstanceBufferSlice Buffer; // 0x10

			// Constructors
			public AddBufferEventArgs(); // 0x00AE59C0-0x00AE59D0
		}

		// Constructors
		public InstanceRenderer(InstanceData source, bool isHdrp); // 0x00AE3440-0x00AE3550

		// Methods
		public virtual void FinalizeFrame(); // 0x00AE5240-0x00AE55D0
		public virtual void Dispose(); // 0x00AE36A0-0x00AE3B90
		public virtual int Add(InstanceBufferSlice buffer, ref List<InstanceBuffer> addedBuffers); // 0x00AE55D0-0x00AE59C0
		public virtual void Remove(InstanceBuffer buffer); // 0x00AE59D0-0x00AE5C00
		public virtual void Render(Camera camera, Plane[] planes, float cullDistance, bool useCache, out int instancesRendered, out int instancesCulled, out int batchesRendered); // 0x00AE5C00-0x00AE68D0
		private bool HasProperties(InstanceBuffer group); // 0x00AE7050-0x00AE7080
		private void SampleLightProbes(MaterialPropertyBlock properties, Matrix4x4[] instances, int instancesCount); // 0x00AE6C80-0x00AE7050
		private void SetColors(MaterialPropertyBlock properties, Vector4[] colors, int count, ref float[] hue, ref float[] saturation, ref float[] lightness); // 0x00AE68D0-0x00AE6C80
	}
}

[ExecuteAlways] // 0x00253000-0x00253010
public class CinemachineCameraOffset : CinemachineExtension // TypeDefIndex: 2559
{
	// Fields
	public Vector3 m_Offset; // 0x28
	public CinemachineCore.Stage m_ApplyAfter; // 0x34
	public bool m_PreserveComposition; // 0x38

	// Constructors
	public CinemachineCameraOffset(); // 0x0068BFC0-0x0068C0A0

	// Methods
	protected override void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime); // 0x0068B8A0-0x0068BFC0
}

public class CinemachineTouchInputMapper : MonoBehaviour // TypeDefIndex: 2560
{
	// Fields
	public float TouchSensitivityX; // 0x18
	public float TouchSensitivityY; // 0x1C
	public string TouchXInputMapTo; // 0x20
	public string TouchYInputMapTo; // 0x28

	// Constructors
	public CinemachineTouchInputMapper(); // 0x004E73B0-0x004E7430

	// Methods
	private void Start(); // 0x004E7220-0x004E72A0
	private float GetInputAxis(string axisName); // 0x004E72A0-0x004E73B0
}

internal sealed class CinemachineMixer : PlayableBehaviour // TypeDefIndex: 2561
{
	// Fields
	private CinemachineBrain mBrain; // 0x10
	private int mBrainOverrideId; // 0x18
	private bool mPlaying; // 0x1C
	private float mLastOverrideTime; // 0x20

	// Nested types
	private struct ClipInfo // TypeDefIndex: 2562
	{
		// Fields
		public ICinemachineCamera vcam; // 0x00
		public float weight; // 0x08
		public double localTime; // 0x10
		public double duration; // 0x18
	}

	// Constructors
	public CinemachineMixer(); // 0x004D0AC0-0x004D0AD0

	// Methods
	public override void OnPlayableDestroy(Playable playable); // 0x004CFE80-0x004CFF90
	public override void PrepareFrame(Playable playable, FrameData info); // 0x004CFF90-0x004CFFA0
	public override void ProcessFrame(Playable playable, FrameData info, object playerData); // 0x004CFFA0-0x004D0860
	private float GetDeltaTime(float deltaTime); // 0x004D0950-0x004D0AC0
}

public sealed class CinemachineShot : PlayableAsset, IPropertyPreview // TypeDefIndex: 2563
{
	// Fields
	public string DisplayName; // 0x18
	public ExposedReference<CinemachineVirtualCameraBase> VirtualCamera; // 0x20

	// Constructors
	public CinemachineShot(); // 0x004DD1E0-0x004DD1F0

	// Methods
	public override Playable CreatePlayable(PlayableGraph graph, GameObject owner); // 0x004DCBE0-0x004DCD20
	public void GatherProperties(PlayableDirector director, IPropertyCollector driver); // 0x004DCD20-0x004DD1E0
}

internal sealed class CinemachineShotPlayable : PlayableBehaviour // TypeDefIndex: 2564
{
	// Fields
	public CinemachineVirtualCameraBase VirtualCamera; // 0x10

	// Properties
	public bool IsValid { get; } // 0x004D0860-0x004D0950

	// Constructors
	public CinemachineShotPlayable(); // 0x004DD1F0-0x004DD200
}

[Serializable]
[TrackBindingType] // 0x00253010-0x00253080
[TrackClipType] // 0x00253010-0x00253080
public class CinemachineTrack : TrackAsset // TypeDefIndex: 2565
{
	// Constructors
	public CinemachineTrack(); // 0x004E74D0-0x004E7520

	// Methods
	public override Playable CreateTrackMixer(PlayableGraph graph, GameObject go, int inputCount); // 0x004E7430-0x004E74D0
}

namespace Cinemachine
{
	[DisallowMultipleComponent] // 0x00253080-0x00253090
	[ExecuteAlways] // 0x00253080-0x00253090
	public class CinemachineBlendListCamera : CinemachineVirtualCameraBase // TypeDefIndex: 2566
	{
		// Fields
		public Transform m_LookAt; // 0x60
		public Transform m_Follow; // 0x68
		public bool m_ShowDebugText; // 0x70
		public bool m_Loop; // 0x71
		[SerializeField] // 0x002531B0-0x002531C0
		internal CinemachineVirtualCameraBase[] m_ChildCameras; // 0x78
		public Instruction[] m_Instructions; // 0x80
		private ICinemachineCamera <LiveChild>k__BackingField; // 0x88
		private ICinemachineCamera <TransitioningFrom>k__BackingField; // 0x90
		private CameraState m_State; // 0x98
		private float mActivationTime; // 0x178
		private int mCurrentInstruction; // 0x17C
		private CinemachineBlend mActiveBlend; // 0x180

		// Properties
		public override string Description { get; } // 0x00684270-0x00684400
		public ICinemachineCamera LiveChild { get; set; } // 0x00684410-0x00684420 0x00684400-0x00684410
		public override CameraState State { get; } // 0x00684440-0x00684460
		public override Transform LookAt { get; set; } // 0x00684460-0x00684470 0x00684470-0x00684480
		public override Transform Follow { get; set; } // 0x00684480-0x00684490 0x00684490-0x006844A0
		private ICinemachineCamera TransitioningFrom { get; set; } // 0x00684E20-0x00684E30 0x00684E30-0x00684E40
		public CinemachineVirtualCameraBase[] ChildCameras { get; } // 0x00686750-0x00686760
		public bool IsBlending { get; } // 0x00686760-0x00686770

		// Nested types
		[Serializable]
		public struct Instruction // TypeDefIndex: 2567
		{
			// Fields
			public CinemachineVirtualCameraBase m_VirtualCamera; // 0x00
			public float m_Hold; // 0x08
			public CinemachineBlendDefinition m_Blend; // 0x10
		}

		// Constructors
		public CinemachineBlendListCamera(); // 0x00686770-0x00686800

		// Methods
		public override bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A797 */); // 0x00684420-0x00684440
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x006844A0-0x006845C0
		public override void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x00684D40-0x00684E20
		public override void InternalUpdateCameraState(Vector3 worldUp, float deltaTime); // 0x00684E40-0x00685500
		protected override void OnEnable(); // 0x00685F70-0x00686090
		protected override void OnDisable(); // 0x006860B0-0x00686160
		private void OnTransformChildrenChanged(); // 0x00686160-0x00686180
		private void OnGuiHandler(); // 0x00686180-0x00686380
		private void InvalidateListOfChildren(); // 0x00686090-0x006860B0
		private void UpdateListOfChildren(); // 0x006845C0-0x00684A10
		internal void ValidateInstructions(); // 0x00684A10-0x00684D40
		private void AdvanceCurrentInstruction(float deltaTime); // 0x00685500-0x00685720
	}

	[DisallowMultipleComponent] // 0x00253090-0x002530A0
	[ExecuteAlways] // 0x00253090-0x002530A0
	public class CinemachineBrain : MonoBehaviour // TypeDefIndex: 2568
	{
		// Fields
		public bool m_ShowDebugText; // 0x18
		public bool m_ShowCameraFrustum; // 0x19
		public bool m_IgnoreTimeScale; // 0x1A
		public Transform m_WorldUpOverride; // 0x20
		public UpdateMethod m_UpdateMethod; // 0x28
		public BrainUpdateMethod m_BlendUpdateMethod; // 0x2C
		public CinemachineBlendDefinition m_DefaultBlend; // 0x30
		public CinemachineBlenderSettings m_CustomBlends; // 0x40
		private Camera m_OutputCamera; // 0x48
		public BrainEvent m_CameraCutEvent; // 0x50
		public VcamActivatedEvent m_CameraActivatedEvent; // 0x58
		private static ICinemachineCamera mSoloCamera; // 0x00
		private Coroutine mPhysicsCoroutine; // 0x60
		private WaitForFixedUpdate mWaitForFixedUpdate; // 0x68
		private List<BrainFrame> mFrameStack; // 0x70
		private int mNextFrameId; // 0x78
		private CinemachineBlend mCurrentLiveCameras; // 0x80
		private ICinemachineCamera mActiveCameraPreviousFrame; // 0x88
		private CameraState <CurrentCameraState>k__BackingField; // 0x90

		// Properties
		public Camera OutputCamera { get; } // 0x00686AB0-0x00686BF0
		public static ICinemachineCamera SoloCamera { get; set; } // 0x00686BF0-0x00686C20 0x00686C20-0x00686DF0
		public Vector3 DefaultWorldUp { get; } // 0x00687010-0x006871E0
		public ICinemachineCamera ActiveVirtualCamera { get; } // 0x006892A0-0x006892F0
		public bool IsBlending { get; } // 0x006891B0-0x00689220
		public CinemachineBlend ActiveBlend { get; } // 0x00689220-0x006892A0
		public CameraState CurrentCameraState { get; private set; } // 0x0068B650-0x0068B670 0x0068B670-0x0068B690

		// Nested types
		public enum UpdateMethod // TypeDefIndex: 2569
		{
			FixedUpdate = 0,
			LateUpdate = 1,
			SmartUpdate = 2
		}

		public enum BrainUpdateMethod // TypeDefIndex: 2570
		{
			FixedUpdate = 0,
			LateUpdate = 1
		}

		[Serializable]
		public class BrainEvent : UnityEvent<CinemachineBrain> // TypeDefIndex: 2571
		{
			// Constructors
			public BrainEvent(); // 0x00AB2A10-0x00AB2A50
		}

		[Serializable]
		public class VcamActivatedEvent : UnityEvent<ICinemachineCamera, ICinemachineCamera> // TypeDefIndex: 2572
		{
			// Constructors
			public VcamActivatedEvent(); // 0x00AB2B90-0x00AB2BD0
		}

		private class BrainFrame // TypeDefIndex: 2573
		{
			// Fields
			public int id; // 0x10
			public CinemachineBlend blend; // 0x18
			public CinemachineBlend workingBlend; // 0x20
			public BlendSourceVirtualCamera workingBlendSource; // 0x28
			public float deltaTimeOverride; // 0x30
			public float timeOfOverride; // 0x34

			// Properties
			public bool Active { get; } // 0x00AB2A50-0x00AB2A70
			public bool TimeOverrideExpired { get; } // 0x00AB2A70-0x00AB2B10

			// Constructors
			public BrainFrame(); // 0x00AB2B10-0x00AB2B90
		}

		private sealed class <AfterPhysics>d__30 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2574
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public CinemachineBrain <>4__this; // 0x20

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00253670-0x00253680 */ get; } // 0x00AB29F0-0x00AB2A00
			object IEnumerator.Current { [DebuggerHidden] /* 0x00253680-0x00253690 */ get; } // 0x00AB2A00-0x00AB2A10

			// Constructors
			[DebuggerHidden] // 0x00253650-0x00253660
			public <AfterPhysics>d__30(int <>1__state); // 0x00AB28B0-0x00AB28C0

			// Methods
			[DebuggerHidden] // 0x00253660-0x00253670
			void IDisposable.Dispose(); // 0x00AB28C0-0x00AB28D0
			private bool MoveNext(); // 0x00AB28D0-0x00AB29F0
		}

		// Constructors
		public CinemachineBrain(); // 0x0068B720-0x0068B8A0

		// Methods
		public static Color GetSoloGUIColor(); // 0x00686FC0-0x00687010
		private void OnEnable(); // 0x006871E0-0x00687430
		private void OnDisable(); // 0x00687540-0x006876A0
		private void Start(); // 0x00687720-0x00687730
		private void OnGuiHandler(); // 0x00688B70-0x00689090
		private IEnumerator AfterPhysics(); // 0x006874F0-0x00687540
		private void LateUpdate(); // 0x006892F0-0x006894F0
		private float GetEffectiveDeltaTime(bool fixedDelta); // 0x006894F0-0x006897B0
		private void UpdateVirtualCameras(CinemachineCore.UpdateFilter updateFilter, float deltaTime); // 0x00687730-0x00687B60
		private static ICinemachineCamera DeepCamBFromBlend(CinemachineBlend blend); // 0x00689090-0x006891B0
		private int GetBrainFrame(int withId); // 0x0068B330-0x0068B470
		internal int SetCameraOverride(int overrideId, ICinemachineCamera camA, ICinemachineCamera camB, float weightB, float deltaTime); // 0x0068B470-0x0068B5B0
		internal void ReleaseCameraOverride(int overrideId); // 0x0068B5B0-0x0068B650
		private void ProcessActiveCamera(float deltaTime); // 0x00689F50-0x0068A4B0
		private void UpdateFrame0(float deltaTime); // 0x006897B0-0x00689BF0
		private void UpdateCurrentLiveCameras(); // 0x00689BF0-0x00689F50
		public bool IsLive(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A798 */); // 0x00685C30-0x00685EE0
		private ICinemachineCamera TopCameraFromPriorityQueue(); // 0x0068AB10-0x0068B060
		private CinemachineBlendDefinition LookupBlend(ICinemachineCamera fromKey, ICinemachineCamera toKey); // 0x0068B060-0x0068B330
		private void PushStateToUnityCamera(CameraState state); // 0x0068A4B0-0x0068AB10
	}

	[DisallowMultipleComponent] // 0x002530A0-0x002530B0
	[ExecuteAlways] // 0x002530A0-0x002530B0
	public class CinemachineClearShot : CinemachineVirtualCameraBase // TypeDefIndex: 2575
	{
		// Fields
		public Transform m_LookAt; // 0x60
		public Transform m_Follow; // 0x68
		public bool m_ShowDebugText; // 0x70
		[SerializeField] // 0x002531C0-0x002531D0
		internal CinemachineVirtualCameraBase[] m_ChildCameras; // 0x78
		public float m_ActivateAfter; // 0x80
		public float m_MinDuration; // 0x84
		public bool m_RandomizeChoice; // 0x88
		public CinemachineBlendDefinition m_DefaultBlend; // 0x90
		public CinemachineBlenderSettings m_CustomBlends; // 0xA0
		private ICinemachineCamera <LiveChild>k__BackingField; // 0xA8
		private CameraState m_State; // 0xB0
		private float mActivationTime; // 0x190
		private float mPendingActivationTime; // 0x194
		private ICinemachineCamera mPendingCamera; // 0x198
		private CinemachineBlend mActiveBlend; // 0x1A0
		private bool mRandomizeNow; // 0x1A8
		private CinemachineVirtualCameraBase[] m_RandomizedChilden; // 0x1B0
		private ICinemachineCamera <TransitioningFrom>k__BackingField; // 0x1B8

		// Properties
		public override string Description { get; } // 0x0068C0E0-0x0068C270
		public ICinemachineCamera LiveChild { get; set; } // 0x0068C280-0x0068C290 0x0068C270-0x0068C280
		public override CameraState State { get; } // 0x0068C290-0x0068C2B0
		public override Transform LookAt { get; set; } // 0x0068C2D0-0x0068C2E0 0x0068C2E0-0x0068C2F0
		public override Transform Follow { get; set; } // 0x0068C2F0-0x0068C300 0x0068C300-0x0068C310
		public bool IsBlending { get; } // 0x0068DF70-0x0068DF80
		public CinemachineVirtualCameraBase[] ChildCameras { get; } // 0x0068DF80-0x0068DF90
		private ICinemachineCamera TransitioningFrom { get; set; } // 0x0068E050-0x0068E060 0x0068E060-0x0068E070

		// Nested types
		private struct Pair // TypeDefIndex: 2576
		{
			// Fields
			public int a; // 0x00
			public float b; // 0x04
		}

		[Serializable]
		private sealed class <>c // TypeDefIndex: 2577
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static Comparison<Pair> <>9__46_0; // 0x08

			// Constructors
			static <>c(); // 0x00AB2BD0-0x00AB2C10
			public <>c(); // 0x00AB2C10-0x00AB2C20

			// Methods
			internal int <Randomize>b__46_0(Pair p1, Pair p2); // 0x00AB2C20-0x00AB2C40
		}

		// Constructors
		public CinemachineClearShot(); // 0x0068E070-0x0068E100

		// Methods
		public override bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A7AD */); // 0x0068C2B0-0x0068C2D0
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x0068C310-0x0068C430
		public override void InternalUpdateCameraState(Vector3 worldUp, float deltaTime); // 0x0068C8A0-0x0068CCA0
		protected override void OnEnable(); // 0x0068DB50-0x0068DC80
		protected override void OnDisable(); // 0x0068DCA0-0x0068DD50
		public void OnTransformChildrenChanged(); // 0x0068DD50-0x0068DD70
		private void OnGuiHandler(); // 0x0068DD70-0x0068DF70
		private void InvalidateListOfChildren(); // 0x0068DC80-0x0068DCA0
		public void ResetRandomization(); // 0x0068DF90-0x0068DFB0
		private void UpdateListOfChildren(); // 0x0068C430-0x0068C8A0
		private ICinemachineCamera ChooseCurrentCamera(Vector3 worldUp); // 0x0068CCA0-0x0068D4F0
		private CinemachineVirtualCameraBase[] Randomize(CinemachineVirtualCameraBase[] src); // 0x0068D7C0-0x0068DB50
		private CinemachineBlendDefinition LookupBlend(ICinemachineCamera fromKey, ICinemachineCamera toKey); // 0x0068D4F0-0x0068D7C0
		public override void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x0068DFB0-0x0068E050
	}

	[ExecuteAlways] // 0x002530B0-0x002530C0
	public class CinemachineCollider : CinemachineExtension // TypeDefIndex: 2578
	{
		// Fields
		public LayerMask m_CollideAgainst; // 0x28
		public string m_IgnoreTag; // 0x30
		public LayerMask m_TransparentLayers; // 0x38
		public float m_MinimumDistanceFromTarget; // 0x3C
		[FormerlySerializedAs] // 0x002531D0-0x002531F0
		public bool m_AvoidObstacles; // 0x40
		[FormerlySerializedAs] // 0x002531F0-0x00253210
		public float m_DistanceLimit; // 0x44
		public float m_MinimumOcclusionTime; // 0x48
		public float m_CameraRadius; // 0x4C
		public ResolutionStrategy m_Strategy; // 0x50
		public int m_MaximumEffort; // 0x54
		public float m_SmoothingTime; // 0x58
		[FormerlySerializedAs] // 0x00253210-0x00253230
		public float m_Damping; // 0x5C
		public float m_DampingWhenOccluded; // 0x60
		public float m_OptimalTargetDistance; // 0x64
		private const float PrecisionSlush = 0.001f; // Metadata: 0x0015A7AE
		private RaycastHit[] m_CornerBuffer; // 0x68
		private const float AngleThreshold = 0.1f; // Metadata: 0x0015A7B2
		private Collider[] mColliderBuffer; // 0x70
		private static SphereCollider mCameraCollider; // 0x00
		private static GameObject mCameraColliderGameObject; // 0x08

		// Properties
		public List<List<Vector3>> DebugPaths { get; } // 0x0068E460-0x0068E5C0

		// Nested types
		public enum ResolutionStrategy // TypeDefIndex: 2579
		{
			PullCameraForward = 0,
			PreserveCameraHeight = 1,
			PreserveCameraDistance = 2
		}

		private class VcamExtraState // TypeDefIndex: 2580
		{
			// Fields
			public Vector3 m_previousDisplacement; // 0x10
			public Vector3 m_previousDisplacementCorrection; // 0x1C
			public float colliderDisplacement; // 0x28
			public bool targetObscured; // 0x2C
			public float occlusionStartTime; // 0x30
			public List<Vector3> debugResolutionPath; // 0x38
			private float m_SmoothedDistance; // 0x40
			private float m_SmoothedTime; // 0x44

			// Constructors
			public VcamExtraState(); // 0x00AB2E30-0x00AB43D0

			// Methods
			public void AddPointToDebugPath(Vector3 p); // 0x00AB2C40-0x00AB2C50
			public float ApplyDistanceSmoothing(float distance, float smoothingTime); // 0x00AB2C50-0x00AB2D40
			public void UpdateDistanceSmoothing(float distance, float smoothingTime); // 0x00AB2D40-0x00AB2DC0
			public void ResetDistanceSmoothing(float smoothingTime); // 0x00AB2DC0-0x00AB2E30
		}

		// Constructors
		public CinemachineCollider(); // 0x00695A80-0x00695B50

		// Methods
		public bool IsTargetObscured(ICinemachineCamera vcam); // 0x0068E100-0x0068E150
		public bool CameraWasDisplaced(ICinemachineCamera vcam); // 0x0068E150-0x0068E1B0
		private void OnValidate(); // 0x0068E1B0-0x0068E250
		protected override void OnDestroy(); // 0x0068E250-0x0068E280
		protected override void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime); // 0x0068E5C0-0x0068F850
		private Vector3 PreserveLignOfSight(ref CameraState state, ref VcamExtraState extra); // 0x0068F850-0x0068FF50
		private Vector3 PullCameraInFrontOfNearestObstacle(Vector3 cameraPos, Vector3 lookAtPos, int layerMask, ref RaycastHit hitInfo); // 0x00692A30-0x00692FB0
		private bool RaycastIgnoreTag(Ray ray, out RaycastHit hitInfo, float rayLength, int layerMask); // 0x006925A0-0x00692A30
		private Vector3 PushCameraBack(Vector3 currentPos, Vector3 pushDir, RaycastHit obstacle, Vector3 lookAtPos, Plane startPlane, float targetDistance, int iterations, ref VcamExtraState extra); // 0x00692FB0-0x00693A50
		private bool GetWalkingDirection(Vector3 pos, Vector3 pushDir, RaycastHit obstacle, ref Vector3 outDir); // 0x00693A50-0x006947B0
		private float GetPushBackDistance(Ray ray, Plane startPlane, float targetDistance, Vector3 lookAtPos); // 0x006947B0-0x00694B10
		private float ClampRayToBounds(Ray ray, float distance, Bounds bounds); // 0x00694B10-0x00695980
		private static void DestroyCollider(); // 0x0068E280-0x0068E440
		private Vector3 RespectCameraRadius(Vector3 cameraPos, ref CameraState state); // 0x0068FF50-0x006916C0
		private bool CheckForTargetObstructions(CameraState state); // 0x00692160-0x006925A0
		private bool IsTargetOffscreen(CameraState state); // 0x006916C0-0x00692160
	}

	[ExecuteAlways] // 0x002530C0-0x002530D0
	public class CinemachineConfiner : CinemachineExtension // TypeDefIndex: 2581
	{
		// Fields
		public Mode m_ConfineMode; // 0x28
		public Collider m_BoundingVolume; // 0x30
		public Collider2D m_BoundingShape2D; // 0x38
		public bool m_ConfineScreenEdges; // 0x40
		public float m_Damping; // 0x44
		private List<List<Vector2>> m_pathCache; // 0x48
		private int m_pathTotalPointCount; // 0x50

		// Properties
		public bool IsValid { get; } // 0x0069B910-0x0069BAE0

		// Nested types
		public enum Mode // TypeDefIndex: 2582
		{
			Confine2D = 0,
			Confine3D = 1
		}

		private class VcamExtraState // TypeDefIndex: 2583
		{
			// Fields
			public Vector3 m_previousDisplacement; // 0x10
			public float confinerDisplacement; // 0x1C

			// Constructors
			public VcamExtraState(); // 0x00AB43D0-0x00AB43E0
		}

		// Constructors
		public CinemachineConfiner(); // 0x0069DBD0-0x0069DC20

		// Methods
		public bool CameraWasDisplaced(CinemachineVirtualCameraBase vcam); // 0x0069B840-0x0069B8A0
		private void OnValidate(); // 0x0069B8A0-0x0069B910
		protected override void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime); // 0x0069BAE0-0x0069BF30
		public void InvalidatePathCache(); // 0x0069DBC0-0x0069DBD0
		private bool ValidatePathCache(); // 0x0069D3C0-0x0069DBC0
		private Vector3 ConfinePoint(Vector3 camPos); // 0x0069CC10-0x0069D3C0
		private Vector3 ConfineScreenEdges(CinemachineVirtualCameraBase vcam, ref CameraState state); // 0x0069BF30-0x0069CC10
	}

	[ExecuteAlways] // 0x002530D0-0x002530E0
	public class CinemachineDollyCart : MonoBehaviour // TypeDefIndex: 2584
	{
		// Fields
		public CinemachinePathBase m_Path; // 0x18
		public UpdateMethod m_UpdateMethod; // 0x20
		public CinemachinePathBase.PositionUnits m_PositionUnits; // 0x24
		[FormerlySerializedAs] // 0x00253230-0x00253250
		public float m_Speed; // 0x28
		[FormerlySerializedAs] // 0x00253250-0x00253270
		public float m_Position; // 0x2C

		// Nested types
		public enum UpdateMethod // TypeDefIndex: 2585
		{
			Update = 0,
			FixedUpdate = 1,
			LateUpdate = 2
		}

		// Constructors
		public CinemachineDollyCart(); // 0x0069F2F0-0x0069F340

		// Methods
		private void FixedUpdate(); // 0x0069EE30-0x0069EEC0
		private void Update(); // 0x0069F160-0x0069F220
		private void LateUpdate(); // 0x0069F220-0x0069F2F0
		private void SetCartPosition(float distanceAlongPath); // 0x0069EEC0-0x0069F160
	}

	[DisallowMultipleComponent] // 0x002530E0-0x00253120
	[ExecuteAlways] // 0x002530E0-0x00253120
	[RequireComponent] // 0x002530E0-0x00253120
	public class CinemachineExternalCamera : CinemachineVirtualCameraBase // TypeDefIndex: 2586
	{
		// Fields
		public Transform m_LookAt; // 0x60
		private Camera m_Camera; // 0x68
		private CameraState m_State; // 0x70
		private Transform <Follow>k__BackingField; // 0x150
		[FormerlySerializedAs] // 0x00253270-0x00253290
		public BlendHint m_BlendHint; // 0x158

		// Properties
		public override CameraState State { get; } // 0x0069F890-0x0069F8B0
		public override Transform LookAt { get; set; } // 0x0069F8B0-0x0069F8C0 0x0069F8C0-0x0069F8D0
		public override Transform Follow { get; set; } // 0x0069F8D0-0x0069F8E0 0x0069F8E0-0x0069F8F0

		// Constructors
		public CinemachineExternalCamera(); // 0x006A0380-0x006A0400

		// Methods
		public override void InternalUpdateCameraState(Vector3 worldUp, float deltaTime); // 0x0069F8F0-0x006A0380
	}

	[ExecuteAlways] // 0x00253120-0x00253130
	public class CinemachineFollowZoom : CinemachineExtension // TypeDefIndex: 2587
	{
		// Fields
		public float m_Width; // 0x28
		public float m_Damping; // 0x2C
		public float m_MinFOV; // 0x30
		public float m_MaxFOV; // 0x34

		// Nested types
		private class VcamExtraState // TypeDefIndex: 2588
		{
			// Fields
			public float m_previousFrameZoom; // 0x10

			// Constructors
			public VcamExtraState(); // 0x00AB51C0-0x00AB51D0
		}

		// Constructors
		public CinemachineFollowZoom(); // 0x006A10E0-0x006A1130

		// Methods
		private void OnValidate(); // 0x006A08F0-0x006A09A0
		protected override void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime); // 0x006A09A0-0x006A10E0
	}

	[DisallowMultipleComponent] // 0x00253130-0x00253140
	[ExecuteAlways] // 0x00253130-0x00253140
	public class CinemachineFreeLook : CinemachineVirtualCameraBase // TypeDefIndex: 2589
	{
		// Fields
		public Transform m_LookAt; // 0x60
		public Transform m_Follow; // 0x68
		[FormerlySerializedAs] // 0x00253290-0x002532B0
		public bool m_CommonLens; // 0x70
		[FormerlySerializedAs] // 0x002532B0-0x002532D0
		public LensSettings m_Lens; // 0x74
		public TransitionParams m_Transitions; // 0xA0
		[FormerlySerializedAs] // 0x002532D0-0x00253310
		[FormerlySerializedAs] // 0x002532D0-0x00253310
		[SerializeField] // 0x002532D0-0x00253310
		private BlendHint m_LegacyBlendHint; // 0xB0
		public AxisState m_YAxis; // 0xB8
		public AxisState.Recentering m_YAxisRecentering; // 0x110
		public AxisState m_XAxis; // 0x130
		public CinemachineOrbitalTransposer.Heading m_Heading; // 0x188
		public AxisState.Recentering m_RecenterToTargetHeading; // 0x194
		public CinemachineTransposer.BindingMode m_BindingMode; // 0x1B0
		[FormerlySerializedAs] // 0x00253310-0x00253330
		public float m_SplineCurvature; // 0x1B4
		public Orbit[] m_Orbits; // 0x1B8
		[FormerlySerializedAs] // 0x00253330-0x00253350
		[SerializeField] // 0x00253330-0x00253350
		private float m_LegacyHeadingBias; // 0x1C0
		private bool mUseLegacyRigDefinitions; // 0x1C4
		private bool mIsDestroyed; // 0x1C5
		private CameraState m_State; // 0x1C8
		[SerializeField] // 0x00253350-0x00253360
		private CinemachineVirtualCamera[] m_Rigs; // 0x2A8
		private CinemachineOrbitalTransposer[] mOrbitals; // 0x2B0
		private CinemachineBlend mBlendA; // 0x2B8
		private CinemachineBlend mBlendB; // 0x2C0
		public static CreateRigDelegate CreateRigOverride; // 0x00
		public static DestroyRigDelegate DestroyRigOverride; // 0x08
		private float <CachedXAxisHeading>k__BackingField; // 0x2C8
		private Orbit[] m_CachedOrbits; // 0x2D0
		private float m_CachedTension; // 0x2D8
		private Vector4[] m_CachedKnots; // 0x2E0
		private Vector4[] m_CachedCtrl1; // 0x2E8
		private Vector4[] m_CachedCtrl2; // 0x2F0

		// Properties
		public static string[] RigNames { get; } // 0x004C1260-0x004C1470
		public override bool PreviousStateIsValid { get; set; } // 0x004C5180-0x004C5190 0x004C5190-0x004C5210
		public override CameraState State { get; } // 0x004C5210-0x004C5230
		public override Transform LookAt { get; set; } // 0x004C5230-0x004C5240 0x004C5450-0x004C5460
		public override Transform Follow { get; set; } // 0x004C5460-0x004C5470 0x004C5680-0x004C5690
		private float CachedXAxisHeading { get; set; } // 0x004CA840-0x004CA850 0x004CA850-0x004CA860

		// Nested types
		[Serializable]
		public struct Orbit // TypeDefIndex: 2590
		{
			// Fields
			public float m_Height; // 0x00
			public float m_Radius; // 0x04

			// Constructors
			public Orbit(float h, float r); // 0x00280680-0x00280800
		}

		public delegate CinemachineVirtualCamera CreateRigDelegate(CinemachineFreeLook vcam, string name, CinemachineVirtualCamera copyFrom); // TypeDefIndex: 2591; 0x00AB51E0-0x00AB5730

		public delegate void DestroyRigDelegate(GameObject rig); // TypeDefIndex: 2592; 0x00AB5790-0x00AB5BC0

		// Constructors
		public CinemachineFreeLook(); // 0x004CB7E0-0x004CBB20

		// Methods
		protected override void OnValidate(); // 0x004C0C70-0x004C0F40
		public CinemachineVirtualCamera GetRig(int i); // 0x004C0FB0-0x004C1000
		protected override void OnEnable(); // 0x004C45A0-0x004C45C0
		protected override void OnDestroy(); // 0x004C4C60-0x004C5090
		private void OnTransformChildrenChanged(); // 0x004C5160-0x004C5170
		private void Reset(); // 0x004C5170-0x004C5180
		public override bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A7D6 */); // 0x004C5690-0x004C5750
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x004C5780-0x004C58A0
		public override void InternalUpdateCameraState(Vector3 worldUp, float deltaTime); // 0x004C5940-0x004C60C0
		public override void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x004C7CA0-0x004C83B0
		private float GetYAxisClosestValue(Vector3 cameraPos, Vector3 up); // 0x004C9130-0x004C9DD0
		private void InvalidateRigCache(); // 0x004C0FA0-0x004C0FB0
		private void DestroyRigs(); // 0x004C2410-0x004C2CD0
		private CinemachineVirtualCamera[] CreateRigs(CinemachineVirtualCamera[] copyFrom); // 0x004C2CD0-0x004C3450
		private void UpdateRigCache(); // 0x004C1000-0x004C1260
		private int LocateExistingRigs(string[] rigNames, bool forceOrbital); // 0x004C1470-0x004C2410
		private float UpdateXAxisHeading(CinemachineOrbitalTransposer orbital, float deltaTime, Vector3 up); // 0x004CA860-0x004CA9F0
		private void PushSettingsToRigs(); // 0x004C65E0-0x004C6E30
		private float GetYAxisValue(); // 0x004C5750-0x004C5780
		private CameraState CalculateNewState(Vector3 worldUp, float deltaTime); // 0x004C60C0-0x004C6280
		public Vector3 GetLocalPositionForCameraFromInput(float t); // 0x004C6E30-0x004C7220
		private void UpdateCachedSpline(); // 0x004C7220-0x004C7820
	}

	[DisallowMultipleComponent] // 0x00253140-0x00253150
	[ExecuteAlways] // 0x00253140-0x00253150
	public class CinemachineMixingCamera : CinemachineVirtualCameraBase // TypeDefIndex: 2593
	{
		// Fields
		public const int MaxCameras = 8; // Metadata: 0x0015A7D8
		public float m_Weight0; // 0x5C
		public float m_Weight1; // 0x60
		public float m_Weight2; // 0x64
		public float m_Weight3; // 0x68
		public float m_Weight4; // 0x6C
		public float m_Weight5; // 0x70
		public float m_Weight6; // 0x74
		public float m_Weight7; // 0x78
		private CameraState m_State; // 0x80
		private ICinemachineCamera <LiveChild>k__BackingField; // 0x160
		private Transform <LookAt>k__BackingField; // 0x168
		private Transform <Follow>k__BackingField; // 0x170
		private CinemachineVirtualCameraBase[] m_ChildCameras; // 0x178
		private Dictionary<CinemachineVirtualCameraBase, int> m_indexMap; // 0x180

		// Properties
		private ICinemachineCamera LiveChild { get; set; } // 0x004D14F0-0x004D1500 0x004D14E0-0x004D14F0
		public override CameraState State { get; } // 0x004D1500-0x004D1520
		public override Transform LookAt { get; set; } // 0x004D1520-0x004D1530 0x004D1530-0x004D1540
		public override Transform Follow { get; set; } // 0x004D1540-0x004D1550 0x004D1550-0x004D1560
		public CinemachineVirtualCameraBase[] ChildCameras { get; } // 0x004D1CE0-0x004D1D00

		// Constructors
		public CinemachineMixingCamera(); // 0x004D2630-0x004D26C0

		// Methods
		public float GetWeight(int index); // 0x004D0AD0-0x004D0BA0
		public void SetWeight(int index, float w); // 0x004D0BA0-0x004D0C70
		public float GetWeight(CinemachineVirtualCameraBase vcam); // 0x004D0C70-0x004D0E30
		public void SetWeight(CinemachineVirtualCameraBase vcam, float w); // 0x004D1310-0x004D14E0
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x004D1560-0x004D1680
		protected override void OnEnable(); // 0x004D1680-0x004D16A0
		public void OnTransformChildrenChanged(); // 0x004D16C0-0x004D16E0
		protected override void OnValidate(); // 0x004D16E0-0x004D1B50
		public override bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A7D7 */); // 0x004D1B50-0x004D1CE0
		protected void InvalidateListOfChildren(); // 0x004D16A0-0x004D16C0
		protected void ValidateListOfChildren(); // 0x004D0E30-0x004D1300
		public override void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x004D1D00-0x004D2340
		public override void InternalUpdateCameraState(Vector3 worldUp, float deltaTime); // 0x004D2340-0x004D2630
	}

	public class CinemachinePath : CinemachinePathBase // TypeDefIndex: 2594
	{
		// Fields
		public bool m_Looped; // 0x48
		public Waypoint[] m_Waypoints; // 0x50

		// Properties
		public override float MinPos { get; } // 0x004D7B60-0x004D7B70
		public override float MaxPos { get; } // 0x004D7B70-0x004D7BA0
		public override bool Looped { get; } // 0x004D7BA0-0x004D7BB0
		public override int DistanceCacheSampleStepsPerSegment { get; } // 0x004D7CA0-0x004D7CB0

		// Nested types
		[Serializable]
		public struct Waypoint // TypeDefIndex: 2595
		{
			// Fields
			public Vector3 position; // 0x00
			public Vector3 tangent; // 0x0C
			public float roll; // 0x18
		}

		// Constructors
		public CinemachinePath(); // 0x004D9060-0x004D9120

		// Methods
		private void Reset(); // 0x004D7BB0-0x004D7CA0
		private float GetBoundingIndices(float pos, out int indexA, out int indexB); // 0x004D7CB0-0x004D7EB0
		public override Vector3 EvaluatePosition(float pos); // 0x004D7EB0-0x004D8430
		public override Vector3 EvaluateTangent(float pos); // 0x004D8430-0x004D8980
		public override Quaternion EvaluateOrientation(float pos); // 0x004D8980-0x004D9040
		private void OnValidate(); // 0x004D9040-0x004D9060
	}

	public sealed class CinemachinePipeline : MonoBehaviour // TypeDefIndex: 2596
	{
		// Constructors
		public CinemachinePipeline(); // 0x004DAA50-0x004DAA90
	}

	public class CinemachinePixelPerfect : MonoBehaviour // TypeDefIndex: 2597
	{
		// Constructors
		public CinemachinePixelPerfect(); // 0x004DAA90-0x004DAAD0
	}

	public class CinemachineSmoothPath : CinemachinePathBase // TypeDefIndex: 2598
	{
		// Fields
		public bool m_Looped; // 0x48
		public Waypoint[] m_Waypoints; // 0x50
		private Waypoint[] m_ControlPoints1; // 0x58
		private Waypoint[] m_ControlPoints2; // 0x60
		private bool m_IsLoopedCache; // 0x68

		// Properties
		public override float MinPos { get; } // 0x004DD200-0x004DD210
		public override float MaxPos { get; } // 0x004DD210-0x004DD240
		public override bool Looped { get; } // 0x004DD240-0x004DD250
		public override int DistanceCacheSampleStepsPerSegment { get; } // 0x004DD250-0x004DD260

		// Nested types
		[Serializable]
		public struct Waypoint // TypeDefIndex: 2599
		{
			// Fields
			public Vector3 position; // 0x00
			public float roll; // 0x0C

			// Properties
			internal Vector4 AsVector4 { get; } // 0x00280920-0x00280A20

			// Methods
			internal static Waypoint FromVector4(Vector4 v); // 0x00AB7FE0-0x00AB8020
		}

		// Constructors
		public CinemachineSmoothPath(); // 0x004DE8F0-0x004DE9B0

		// Methods
		private void OnValidate(); // 0x004DD260-0x004DD280
		private void Reset(); // 0x004DD280-0x004DD350
		public override void InvalidateDistanceCache(); // 0x004DD350-0x004DD370
		private void UpdateControlPoints(); // 0x004DD370-0x004DD660
		private float GetBoundingIndices(float pos, out int indexA, out int indexB); // 0x004DD660-0x004DD7D0
		public override Vector3 EvaluatePosition(float pos); // 0x004DD7D0-0x004DDD00
		public override Vector3 EvaluateTangent(float pos); // 0x004DDD00-0x004DE1C0
		public override Quaternion EvaluateOrientation(float pos); // 0x004DE1C0-0x004DE8F0
	}

	[DisallowMultipleComponent] // 0x00253150-0x00253160
	[ExecuteAlways] // 0x00253150-0x00253160
	public class CinemachineStateDrivenCamera : CinemachineVirtualCameraBase // TypeDefIndex: 2600
	{
		// Fields
		public Transform m_LookAt; // 0x60
		public Transform m_Follow; // 0x68
		public Animator m_AnimatedTarget; // 0x70
		public int m_LayerIndex; // 0x78
		public bool m_ShowDebugText; // 0x7C
		[SerializeField] // 0x00253360-0x00253370
		internal CinemachineVirtualCameraBase[] m_ChildCameras; // 0x80
		public Instruction[] m_Instructions; // 0x88
		public CinemachineBlendDefinition m_DefaultBlend; // 0x90
		public CinemachineBlenderSettings m_CustomBlends; // 0xA0
		[SerializeField] // 0x00253370-0x00253380
		internal ParentHash[] m_ParentHash; // 0xA8
		private ICinemachineCamera <LiveChild>k__BackingField; // 0xB0
		private ICinemachineCamera <TransitioningFrom>k__BackingField; // 0xB8
		private CameraState m_State; // 0xC0
		private Dictionary<AnimationClip, List<HashPair>> mHashCache; // 0x1A0
		private float mActivationTime; // 0x1A8
		private Instruction mActiveInstruction; // 0x1B0
		private float mPendingActivationTime; // 0x1C8
		private Instruction mPendingInstruction; // 0x1D0
		private CinemachineBlend mActiveBlend; // 0x1E8
		private Dictionary<int, int> mInstructionDictionary; // 0x1F0
		private Dictionary<int, int> mStateParentLookup; // 0x1F8
		private List<AnimatorClipInfo> m_clipInfoList; // 0x200

		// Properties
		public override string Description { get; } // 0x004DE9B0-0x004DEAD0
		public ICinemachineCamera LiveChild { get; set; } // 0x004DEAE0-0x004DEAF0 0x004DEAD0-0x004DEAE0
		public override CameraState State { get; } // 0x004DEB10-0x004DEB30
		public override Transform LookAt { get; set; } // 0x004DEB30-0x004DEB40 0x004DEB40-0x004DEB50
		public override Transform Follow { get; set; } // 0x004DEB50-0x004DEB60 0x004DEB60-0x004DEB70
		private ICinemachineCamera TransitioningFrom { get; set; } // 0x004DF6C0-0x004DF6D0 0x004DF6D0-0x004DF6E0
		public CinemachineVirtualCameraBase[] ChildCameras { get; } // 0x004E1280-0x004E12A0
		public bool IsBlending { get; } // 0x004E12A0-0x004E12B0

		// Nested types
		[Serializable]
		public struct Instruction // TypeDefIndex: 2601
		{
			// Fields
			public int m_FullHash; // 0x00
			public CinemachineVirtualCameraBase m_VirtualCamera; // 0x08
			public float m_ActivateAfter; // 0x10
			public float m_MinDuration; // 0x14
		}

		[Serializable]
		internal struct ParentHash // TypeDefIndex: 2602
		{
			// Fields
			public int m_Hash; // 0x00
			public int m_ParentHash; // 0x04
		}

		private struct HashPair // TypeDefIndex: 2603
		{
			// Fields
			public int parentHash; // 0x00
			public int hash; // 0x04
		}

		// Constructors
		public CinemachineStateDrivenCamera(); // 0x004E13A0-0x004E1470

		// Methods
		public override bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A7DC */); // 0x004DEAF0-0x004DEB10
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x004DEB70-0x004DEC90
		public override void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x004DF5A0-0x004DF6C0
		public override void InternalUpdateCameraState(Vector3 worldUp, float deltaTime); // 0x004DF6E0-0x004DFCF0
		protected override void OnEnable(); // 0x004E0E70-0x004E0FA0
		protected override void OnDisable(); // 0x004E0FC0-0x004E1070
		public void OnTransformChildrenChanged(); // 0x004E10D0-0x004E10F0
		private void OnGuiHandler(); // 0x004E10F0-0x004E1280
		public static int CreateFakeHash(int parentHash, AnimationClip clip); // 0x004E12B0-0x004E13A0
		private int LookupFakeHash(int parentHash, AnimationClip clip); // 0x004E0BF0-0x004E0E70
		private void InvalidateListOfChildren(); // 0x004E0FA0-0x004E0FC0
		private void UpdateListOfChildren(); // 0x004DEC90-0x004DF100
		internal void ValidateInstructions(); // 0x004DF100-0x004DF5A0
		private CinemachineVirtualCameraBase ChooseCurrentCamera(); // 0x004DFCF0-0x004E06D0
		private int GetClipHash(int hash, List<AnimatorClipInfo> clips); // 0x004E0AD0-0x004E0BF0
		private CinemachineBlendDefinition LookupBlend(ICinemachineCamera fromKey, ICinemachineCamera toKey); // 0x004E06D0-0x004E09A0
	}

	[ExecuteAlways] // 0x00253160-0x00253170
	public class CinemachineStoryboard : CinemachineExtension // TypeDefIndex: 2604
	{
		// Fields
		public static bool s_StoryboardGlobalMute; // 0x00
		public bool m_ShowImage; // 0x28
		public Texture m_Image; // 0x30
		public FillStrategy m_Aspect; // 0x38
		public float m_Alpha; // 0x3C
		public Vector2 m_Center; // 0x40
		public Vector3 m_Rotation; // 0x48
		public Vector2 m_Scale; // 0x54
		public bool m_SyncScale; // 0x5C
		public bool m_MuteCamera; // 0x5D
		public float m_SplitView; // 0x60
		private List<CanvasInfo> mCanvasInfo; // 0x68

		// Properties
		private string CanvasName { get; } // 0x004E1B60-0x004E1C40

		// Nested types
		public enum FillStrategy // TypeDefIndex: 2605
		{
			BestFit = 0,
			CropImageToFit = 1,
			StretchToFit = 2
		}

		private class CanvasInfo // TypeDefIndex: 2606
		{
			// Fields
			public GameObject mCanvas; // 0x10
			public CinemachineBrain mCanvasParent; // 0x18
			public RectTransform mViewport; // 0x20
			public RawImage mRawImage; // 0x28

			// Constructors
			public CanvasInfo(); // 0x00AB8020-0x00AB80A0
		}

		// Constructors
		public CinemachineStoryboard(); // 0x004E44A0-0x004E4670

		// Methods
		protected override void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float wipeAmountTime); // 0x004E1470-0x004E1550
		protected override void ConnectToVcam(bool connect); // 0x004E1550-0x004E1690
		private void CameraUpdatedCallback(CinemachineBrain brain); // 0x004E1C40-0x004E2000
		private CanvasInfo LocateMyCanvas(CinemachineBrain parent, bool createIfNotFound); // 0x004E2000-0x004E28D0
		private void CreateCanvas(CanvasInfo ci); // 0x004E28D0-0x004E31C0
		private void DestroyCanvas(); // 0x004E1690-0x004E1B60
		private void PlaceImage(CanvasInfo ci, float alpha); // 0x004E31C0-0x004E3F50
		private static void StaticBlendingHandler(CinemachineBrain brain); // 0x004E3F50-0x004E43A0
		[RuntimeInitializeOnLoadMethod] // 0x00253690-0x002536A0
		private static void InitializeModule(); // 0x004E43A0-0x004E44A0
	}

	public interface ICinemachineTargetGroup // TypeDefIndex: 2607
	{
		// Properties
		BoundingSphere Sphere { get; }

		// Methods
		Bounds GetViewSpaceBoundingBox(Matrix4x4 observer);
		void GetViewSpaceAngularBounds(Matrix4x4 observer, out Vector2 minAngles, out Vector2 maxAngles, out Vector2 zRange);
	}

	[ExecuteAlways] // 0x00253170-0x00253180
	public class CinemachineTargetGroup : MonoBehaviour, ICinemachineTargetGroup // TypeDefIndex: 2608
	{
		// Fields
		public PositionMode m_PositionMode; // 0x18
		public RotationMode m_RotationMode; // 0x1C
		public UpdateMethod m_UpdateMethod; // 0x20
		public Target[] m_Targets; // 0x28
		private Bounds <BoundingBox>k__BackingField; // 0x30
		private float mMaxWeight; // 0x48
		private Vector3 mAveragePos; // 0x4C

		// Properties
		public Transform Transform { get; } // 0x004E4670-0x004E46C0
		public Bounds BoundingBox { get; private set; } // 0x004E46C0-0x004E46E0 0x004E46E0-0x004E4700
		public BoundingSphere Sphere { get; } // 0x004E4700-0x004E4970
		public bool IsEmpty { get; } // 0x004E4970-0x004E4B00

		// Nested types
		[Serializable]
		public struct Target // TypeDefIndex: 2609
		{
			// Fields
			public Transform target; // 0x00
			public float weight; // 0x08
			public float radius; // 0x0C
		}

		public enum PositionMode // TypeDefIndex: 2610
		{
			GroupCenter = 0,
			GroupAverage = 1
		}

		public enum RotationMode // TypeDefIndex: 2611
		{
			Manual = 0,
			GroupAverage = 1
		}

		public enum UpdateMethod // TypeDefIndex: 2612
		{
			Update = 0,
			FixedUpdate = 1,
			LateUpdate = 2
		}

		// Constructors
		public CinemachineTargetGroup(); // 0x004E71A0-0x004E7220

		// Methods
		public void AddMember(Transform t, float weight, float radius); // 0x004E4B00-0x004E4BE0
		public void RemoveMember(Transform t); // 0x004E4BE0-0x004E4C80
		public int FindMember(Transform t); // 0x004E4C80-0x004E4DC0
		public BoundingSphere GetWeightedBoundsForMember(int index); // 0x004E4DC0-0x004E4E20
		public Bounds GetViewSpaceBoundingBox(Matrix4x4 observer); // 0x004E5100-0x004E57C0
		private static BoundingSphere WeightedMemberBounds(Target t, Vector3 avgPos, float maxWeight); // 0x004E4E20-0x004E5100
		public void DoUpdate(); // 0x004E57C0-0x004E59A0
		private Vector3 CalculateAveragePosition(out float maxWeight); // 0x004E59A0-0x004E5E70
		private Quaternion CalculateAverageOrientation(); // 0x004E6380-0x004E6680
		private Bounds CalculateBoundingBox(Vector3 avgPos, float maxWeight); // 0x004E5E70-0x004E6380
		private void OnValidate(); // 0x004E6680-0x004E6770
		private void FixedUpdate(); // 0x004E6770-0x004E6780
		private void Update(); // 0x004E6780-0x004E67E0
		private void LateUpdate(); // 0x004E67E0-0x004E67F0
		public void GetViewSpaceAngularBounds(Matrix4x4 observer, out Vector2 minAngles, out Vector2 maxAngles, out Vector2 zRange); // 0x004E67F0-0x004E71A0
	}

	[DisallowMultipleComponent] // 0x00253180-0x00253190
	[ExecuteAlways] // 0x00253180-0x00253190
	public class CinemachineVirtualCamera : CinemachineVirtualCameraBase // TypeDefIndex: 2613
	{
		// Fields
		public Transform m_LookAt; // 0x60
		public Transform m_Follow; // 0x68
		[FormerlySerializedAs] // 0x00253380-0x002533A0
		public LensSettings m_Lens; // 0x70
		public TransitionParams m_Transitions; // 0xA0
		[FormerlySerializedAs] // 0x002533A0-0x002533E0
		[FormerlySerializedAs] // 0x002533A0-0x002533E0
		[SerializeField] // 0x002533A0-0x002533E0
		private BlendHint m_LegacyBlendHint; // 0xB0
		public const string PipelineName = "cm"; // Metadata: 0x0015A805
		public static CreatePipelineDelegate CreatePipelineOverride; // 0x00
		public static DestroyPipelineDelegate DestroyPipelineOverride; // 0x08
		private bool <UserIsDragging>k__BackingField; // 0xB4
		private CameraState m_State; // 0xB8
		private CinemachineComponentBase[] m_ComponentPipeline; // 0x198
		[SerializeField] // 0x002533E0-0x002533F0
		private Transform m_ComponentOwner; // 0x1A0
		private Transform mCachedLookAtTarget; // 0x1A8
		private CinemachineVirtualCameraBase mCachedLookAtTargetVcam; // 0x1B0

		// Properties
		public override CameraState State { get; } // 0x004EA7A0-0x004EA7C0
		public override Transform LookAt { get; set; } // 0x004EA7C0-0x004EA7D0 0x004EA7D0-0x004EA7E0
		public override Transform Follow { get; set; } // 0x004EA7E0-0x004EA7F0 0x004EA7F0-0x004EA800
		public bool UserIsDragging { get; set; } // 0x004EC9E0-0x004EC9F0 0x004EC9F0-0x004ECA00

		// Nested types
		public delegate Transform CreatePipelineDelegate(CinemachineVirtualCamera vcam, string name, CinemachineComponentBase[] copyFrom); // TypeDefIndex: 2614; 0x00AB8EC0-0x00AB9410

		public delegate void DestroyPipelineDelegate(GameObject pipeline); // TypeDefIndex: 2615; 0x00AB9470-0x00AB98A0

		[Serializable]
		private sealed class <>c // TypeDefIndex: 2616
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static Comparison<CinemachineComponentBase> <>9__40_0; // 0x08

			// Constructors
			static <>c(); // 0x00AB8E10-0x00AB8E50
			public <>c(); // 0x00AB8E50-0x00AB8E60

			// Methods
			internal int <UpdateComponentPipeline>b__40_0(CinemachineComponentBase c1, CinemachineComponentBase c2); // 0x00AB8E60-0x00AB8EB0
		}

		// Constructors
		public CinemachineVirtualCamera(); // 0x004ED240-0x004ED310

		// Methods
		public override void InternalUpdateCameraState(Vector3 worldUp, float deltaTime); // 0x004EA800-0x004EABC0
		protected override void OnEnable(); // 0x004EB4C0-0x004EBA40
		protected override void OnDestroy(); // 0x004EBB30-0x004EC170
		protected override void OnValidate(); // 0x004EC170-0x004EC2B0
		private void OnTransformChildrenChanged(); // 0x004EC2B0-0x004EC2C0
		private void Reset(); // 0x004EC2C0-0x004EC2D0
		private void DestroyPipeline(); // 0x004EC2D0-0x004EC9C0
		private Transform CreatePipeline(CinemachineVirtualCamera copyFrom); // 0x004C4190-0x004C43D0
		public void InvalidateComponentPipeline(); // 0x004CA830-0x004CA840
		public Transform GetComponentOwner(); // 0x004CA810-0x004CA830
		public CinemachineComponentBase[] GetComponentPipeline(); // 0x004EC9C0-0x004EC9E0
		public CinemachineComponentBase GetCinemachineComponent(CinemachineCore.Stage stage); // 0x004EBAA0-0x004EBB30
		public T GetCinemachineComponent<T>()
			where T : CinemachineComponentBase;
		public T AddCinemachineComponent<T>()
			where T : CinemachineComponentBase;
		public void DestroyCinemachineComponent<T>()
			where T : CinemachineComponentBase;
		private void UpdateComponentPipeline(); // 0x004C3450-0x004C4190
		internal static void SetFlagsForHiddenChild(GameObject child); // 0x004C43D0-0x004C45A0
		private CameraState CalculateNewState(Vector3 worldUp, float deltaTime); // 0x004EABC0-0x004EB4C0
		private CinemachineCore.Stage AdvancePipelineStage(ref CameraState state, float deltaTime, CinemachineCore.Stage curStage, int maxStage, bool hasAim); // 0x004ECA00-0x004ECAA0
		internal void SetStateRawPosition(Vector3 pos); // 0x004CB7D0-0x004CB7E0
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x004ECAA0-0x004ECDE0
		public override void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x004ECDE0-0x004ED240
	}

	public class CinemachineBasicMultiChannelPerlin : CinemachineComponentBase // TypeDefIndex: 2617
	{
		// Fields
		[FormerlySerializedAs] // 0x002533F0-0x00253410
		public NoiseSettings m_NoiseProfile; // 0x50
		public Vector3 m_PivotOffset; // 0x58
		public float m_AmplitudeGain; // 0x64
		public float m_FrequencyGain; // 0x68
		private bool mInitialized; // 0x6C
		private float mNoiseTime; // 0x70
		[SerializeField] // 0x00253410-0x00253420
		private Vector3 mNoiseOffsets; // 0x74

		// Properties
		public override bool IsValid { get; } // 0x006820E0-0x00682210
		public override CinemachineCore.Stage Stage { get; } // 0x00682210-0x00682220

		// Constructors
		public CinemachineBasicMultiChannelPerlin(); // 0x00683100-0x00683240

		// Methods
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x00682220-0x00682E10
		public void ReSeed(); // 0x00683010-0x00683100
		private void Initialize(); // 0x00682E10-0x00683010
	}

	public class CinemachineComposer : CinemachineComponentBase // TypeDefIndex: 2618
	{
		// Fields
		public Vector3 m_TrackedObjectOffset; // 0x50
		public float m_LookaheadTime; // 0x5C
		public float m_LookaheadSmoothing; // 0x60
		public bool m_LookaheadIgnoreY; // 0x64
		public float m_HorizontalDamping; // 0x68
		public float m_VerticalDamping; // 0x6C
		public float m_ScreenX; // 0x70
		public float m_ScreenY; // 0x74
		public float m_DeadZoneWidth; // 0x78
		public float m_DeadZoneHeight; // 0x7C
		public float m_SoftZoneWidth; // 0x80
		public float m_SoftZoneHeight; // 0x84
		public float m_BiasX; // 0x88
		public float m_BiasY; // 0x8C
		public bool m_CenterOnActivate; // 0x90
		private Vector3 <TrackedPoint>k__BackingField; // 0x94
		private Vector3 m_CameraPosPrevFrame; // 0xA0
		private Vector3 m_LookAtPrevFrame; // 0xAC
		private Vector2 m_ScreenOffsetPrevFrame; // 0xB8
		private Quaternion m_CameraOrientationPrevFrame; // 0xC0
		internal PositionPredictor m_Predictor; // 0xD0
		private FovCache mCache; // 0xD8

		// Properties
		public override bool IsValid { get; } // 0x00698FF0-0x00699130
		public override CinemachineCore.Stage Stage { get; } // 0x00699130-0x00699140
		public Vector3 TrackedPoint { get; private set; } // 0x00699140-0x00699160 0x00699160-0x00699170
		internal Rect SoftGuideRect { get; set; } // 0x0069B110-0x0069B130 0x0069B1D0-0x0069B300
		internal Rect HardGuideRect { get; set; } // 0x0069B130-0x0069B1D0 0x0069B300-0x0069B570

		// Nested types
		private struct FovCache // TypeDefIndex: 2619
		{
			// Fields
			public Rect mFovSoftGuideRect; // 0x00
			public Rect mFovHardGuideRect; // 0x10
			public float mFovH; // 0x20
			public float mFov; // 0x24
			private float mOrthoSizeOverDistance; // 0x28
			private float mAspect; // 0x2C
			private Rect mSoftGuideRect; // 0x30
			private Rect mHardGuideRect; // 0x40

			// Methods
			public void UpdateCache(LensSettings lens, Rect softGuide, Rect hardGuide, float targetDistance); // 0x002805F0-0x00280620
			private Rect ScreenToFOV(Rect rScreen, float fov, float fovH, float aspect); // 0x00280620-0x00280680
		}

		// Constructors
		public CinemachineComposer(); // 0x0069B570-0x0069B840

		// Methods
		protected virtual Vector3 GetLookAtPointAndSetTrackedPoint(Vector3 lookAt, Vector3 up, float deltaTime); // 0x00699170-0x00699640
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x00699640-0x00699800
		public override void PrePipelineMutateCameraState(ref CameraState curState, float deltaTime); // 0x00699800-0x00699900
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x00699900-0x0069AC90
		private void RotateToScreenBounds(ref CameraState state, Rect screenRect, Vector3 trackedPoint, ref Quaternion rigOrientation, float fov, float fovH, float deltaTime); // 0x0069AC90-0x0069AF70
		private bool ClampVerticalBounds(ref Rect r, Vector3 dir, Vector3 up, float fov); // 0x0069AF70-0x0069B110
	}

	public class CinemachineFramingTransposer : CinemachineComponentBase // TypeDefIndex: 2620
	{
		// Fields
		public float m_LookaheadTime; // 0x50
		public float m_LookaheadSmoothing; // 0x54
		public bool m_LookaheadIgnoreY; // 0x58
		public float m_XDamping; // 0x5C
		public float m_YDamping; // 0x60
		public float m_ZDamping; // 0x64
		public float m_ScreenX; // 0x68
		public float m_ScreenY; // 0x6C
		public float m_CameraDistance; // 0x70
		public float m_DeadZoneWidth; // 0x74
		public float m_DeadZoneHeight; // 0x78
		[FormerlySerializedAs] // 0x00253420-0x00253440
		public float m_DeadZoneDepth; // 0x7C
		public bool m_UnlimitedSoftZone; // 0x80
		public float m_SoftZoneWidth; // 0x84
		public float m_SoftZoneHeight; // 0x88
		public float m_BiasX; // 0x8C
		public float m_BiasY; // 0x90
		public bool m_CenterOnActivate; // 0x94
		[FormerlySerializedAs] // 0x00253440-0x00253460
		public FramingMode m_GroupFramingMode; // 0x98
		public AdjustmentMode m_AdjustmentMode; // 0x9C
		public float m_GroupFramingSize; // 0xA0
		public float m_MaxDollyIn; // 0xA4
		public float m_MaxDollyOut; // 0xA8
		public float m_MinimumDistance; // 0xAC
		public float m_MaximumDistance; // 0xB0
		public float m_MinimumFOV; // 0xB4
		public float m_MaximumFOV; // 0xB8
		public float m_MinimumOrthoSize; // 0xBC
		public float m_MaximumOrthoSize; // 0xC0
		private const float kMinimumCameraDistance = 0.01f; // Metadata: 0x0015A80B
		private Vector3 m_PreviousCameraPosition; // 0xC4
		private PositionPredictor m_Predictor; // 0xD0
		private Vector3 <TrackedPoint>k__BackingField; // 0xD8
		private bool <InheritingPosition>k__BackingField; // 0xE4
		private float m_prevFOV; // 0xE8
		private Bounds <LastBounds>k__BackingField; // 0xEC
		private Matrix4x4 <LastBoundsMatrix>k__BackingField; // 0x104

		// Properties
		internal Rect SoftGuideRect { get; set; } // 0x006A1130-0x006A1150 0x006A1150-0x006A1280
		internal Rect HardGuideRect { get; set; } // 0x006A1280-0x006A1320 0x006A1320-0x006A1590
		public override bool IsValid { get; } // 0x006A16A0-0x006A17E0
		public override CinemachineCore.Stage Stage { get; } // 0x006A17E0-0x006A17F0
		public Vector3 TrackedPoint { get; private set; } // 0x006A17F0-0x006A1810 0x006A1810-0x006A1820
		private bool InheritingPosition { get; set; } // 0x006A1B10-0x006A1B20 0x006A1B20-0x006A1B30
		public Bounds LastBounds { get; private set; } // 0x006A1D10-0x006A1D30 0x006A1D30-0x006A1D50
		public Matrix4x4 LastBoundsMatrix { get; private set; } // 0x006A1D50-0x006A1D80 0x006A1D80-0x006A1DC0

		// Nested types
		public enum FramingMode // TypeDefIndex: 2621
		{
			Horizontal = 0,
			Vertical = 1,
			HorizontalAndVertical = 2,
			None = 3
		}

		public enum AdjustmentMode // TypeDefIndex: 2622
		{
			ZoomOnly = 0,
			DollyOnly = 1,
			DollyThenZoom = 2
		}

		// Constructors
		public CinemachineFramingTransposer(); // 0x006A5670-0x006A57E0

		// Methods
		private void OnValidate(); // 0x006A1590-0x006A16A0
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x006A1820-0x006A19B0
		public override bool OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime, ref CinemachineVirtualCameraBase.TransitionParams transitionParams); // 0x006A19B0-0x006A1B10
		private Rect ScreenToOrtho(Rect rScreen, float orthoSize, float aspect); // 0x006A1B30-0x006A1BB0
		private Vector3 OrthoOffsetToScreenBounds(Vector3 targetPos2D, Rect screenRect); // 0x006A1BB0-0x006A1D10
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x006A1DC0-0x006A4080
		private float GetTargetHeight(Vector2 boundsSize); // 0x006A4B30-0x006A4C30
		private Vector3 ComputeGroupBounds(ICinemachineTargetGroup group, ref CameraState curState); // 0x006A4080-0x006A4B30
		private static Bounds GetScreenSpaceGroupBoundingBox(ICinemachineTargetGroup group, ref Vector3 pos, Quaternion orientation); // 0x006A4C30-0x006A5670
	}

	public class CinemachineGroupComposer : CinemachineComposer // TypeDefIndex: 2623
	{
		// Fields
		public float m_GroupFramingSize; // 0x128
		public FramingMode m_FramingMode; // 0x12C
		public float m_FrameDamping; // 0x130
		public AdjustmentMode m_AdjustmentMode; // 0x134
		public float m_MaxDollyIn; // 0x138
		public float m_MaxDollyOut; // 0x13C
		public float m_MinimumDistance; // 0x140
		public float m_MaximumDistance; // 0x144
		public float m_MinimumFOV; // 0x148
		public float m_MaximumFOV; // 0x14C
		public float m_MinimumOrthoSize; // 0x150
		public float m_MaximumOrthoSize; // 0x154
		private float m_prevFramingDistance; // 0x158
		private float m_prevFOV; // 0x15C
		private Bounds <LastBounds>k__BackingField; // 0x160
		private Matrix4x4 <LastBoundsMatrix>k__BackingField; // 0x178

		// Properties
		public Bounds LastBounds { get; private set; } // 0x004CBDA0-0x004CBDC0 0x004CBDC0-0x004CBDE0
		public Matrix4x4 LastBoundsMatrix { get; private set; } // 0x004CBDE0-0x004CBE10 0x004CBE10-0x004CBE50

		// Nested types
		public enum FramingMode // TypeDefIndex: 2624
		{
			Horizontal = 0,
			Vertical = 1,
			HorizontalAndVertical = 2
		}

		public enum AdjustmentMode // TypeDefIndex: 2625
		{
			ZoomOnly = 0,
			DollyOnly = 1,
			DollyThenZoom = 2
		}

		// Constructors
		public CinemachineGroupComposer(); // 0x004CDDF0-0x004CDE30

		// Methods
		private void OnValidate(); // 0x004CBC70-0x004CBDA0
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x004CBE50-0x004CD550
		private float GetTargetHeight(Vector2 boundsSize); // 0x004CDC50-0x004CDDF0
		private static Bounds GetScreenSpaceGroupBoundingBox(ICinemachineTargetGroup group, Matrix4x4 observer, out Vector3 newFwd); // 0x004CD550-0x004CDC50
	}

	public class CinemachineHardLockToTarget : CinemachineComponentBase // TypeDefIndex: 2626
	{
		// Fields
		public float m_Damping; // 0x50
		private Vector3 m_PreviousTargetPosition; // 0x54

		// Properties
		public override bool IsValid { get; } // 0x004CDE30-0x004CDF70
		public override CinemachineCore.Stage Stage { get; } // 0x004CDF70-0x004CDF80

		// Constructors
		public CinemachineHardLockToTarget(); // 0x004CE080-0x004CE0C0

		// Methods
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x004CDF80-0x004CE080
	}

	public class CinemachineHardLookAt : CinemachineComponentBase // TypeDefIndex: 2627
	{
		// Properties
		public override bool IsValid { get; } // 0x004CE0C0-0x004CE200
		public override CinemachineCore.Stage Stage { get; } // 0x004CE200-0x004CE210

		// Constructors
		public CinemachineHardLookAt(); // 0x004CE730-0x004CE770

		// Methods
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x004CE210-0x004CE730
	}

	public class CinemachineOrbitalTransposer : CinemachineTransposer // TypeDefIndex: 2628
	{
		// Fields
		public Heading m_Heading; // 0xB8
		public AxisState.Recentering m_RecenterToTargetHeading; // 0xC4
		public AxisState m_XAxis; // 0xE0
		[FormerlySerializedAs] // 0x00253460-0x00253480
		[SerializeField] // 0x00253460-0x00253480
		private float m_LegacyRadius; // 0x138
		[FormerlySerializedAs] // 0x00253480-0x002534A0
		[SerializeField] // 0x00253480-0x002534A0
		private float m_LegacyHeightOffset; // 0x13C
		[FormerlySerializedAs] // 0x002534A0-0x002534C0
		[SerializeField] // 0x002534A0-0x002534C0
		private float m_LegacyHeadingBias; // 0x140
		public bool m_HeadingIsSlave; // 0x144
		internal UpdateHeadingDelegate HeadingUpdater; // 0x148
		private Vector3 mLastTargetPosition; // 0x150
		private HeadingTracker mHeadingTracker; // 0x160
		private Rigidbody mTargetRigidBody; // 0x168
		private Transform <PreviousTarget>k__BackingField; // 0x170
		private Quaternion mHeadingPrevFrame; // 0x178
		private Vector3 mOffsetPrevFrame; // 0x188
		private float <LastHeading>k__BackingField; // 0x194

		// Properties
		private Transform PreviousTarget { get; set; } // 0x004D2A20-0x004D2A30 0x004D2A30-0x004D2A40
		private float LastHeading { get; set; } // 0x004D2F40-0x004D2F50 0x004D2F50-0x004D2F60

		// Nested types
		[Serializable]
		public struct Heading // TypeDefIndex: 2629
		{
			// Fields
			[FormerlySerializedAs] // 0x002534C0-0x002534E0
			public HeadingDefinition m_Definition; // 0x00
			public int m_VelocityFilterStrength; // 0x04
			[FormerlySerializedAs] // 0x002534E0-0x00253500
			public float m_Bias; // 0x08

			// Nested types
			public enum HeadingDefinition // TypeDefIndex: 2630
			{
				PositionDelta = 0,
				Velocity = 1,
				TargetForward = 2,
				WorldForward = 3
			}

			// Constructors
			public Heading(HeadingDefinition def, int filterStrength, float bias); // 0x00280910-0x00280920
		}

		internal delegate float UpdateHeadingDelegate(CinemachineOrbitalTransposer orbital, float deltaTime, Vector3 up); // TypeDefIndex: 2631; 0x00AB7580-0x00AB7AA0

		[Serializable]
		private sealed class <>c // TypeDefIndex: 2632
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static UpdateHeadingDelegate <>9__34_0; // 0x08

			// Constructors
			static <>c(); // 0x00AB7460-0x00AB74A0
			public <>c(); // 0x00AB74A0-0x00AB74B0

			// Methods
			internal float <.ctor>b__34_0(CinemachineOrbitalTransposer orbital, float deltaTime, Vector3 up); // 0x00AB74B0-0x00AB7570
		}

		// Constructors
		public CinemachineOrbitalTransposer(); // 0x004D5560-0x004D5870

		// Methods
		protected override void OnValidate(); // 0x004D26C0-0x004D28C0
		public float UpdateHeading(float deltaTime, Vector3 up, ref AxisState axis); // 0x004D2950-0x004D2970
		public float UpdateHeading(float deltaTime, Vector3 up, ref AxisState axis, ref AxisState.Recentering recentering, bool isLive); // 0x004CA9F0-0x004CAB40
		private void OnEnable(); // 0x004D2970-0x004D2A20
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x004D2A40-0x004D2C40
		public override bool OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime, ref CinemachineVirtualCameraBase.TransitionParams transitionParams); // 0x004D2D50-0x004D2EC0
		public float GetAxisClosestValue(Vector3 cameraPos, Vector3 up); // 0x004C85D0-0x004C9130
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x004D2F60-0x004D3EA0
		public override Vector3 GetTargetCameraPosition(Vector3 worldUp); // 0x004D4DC0-0x004D5230
		private static string GetFullName(GameObject current); // 0x004D5230-0x004D5560
		private float GetTargetHeading(float currentHeading, Quaternion targetOrientation); // 0x004CAB40-0x004CB7D0
	}

	public class CinemachinePOV : CinemachineComponentBase // TypeDefIndex: 2633
	{
		// Fields
		public bool m_ApplyBeforeBody; // 0x50
		public RecenterTargetMode m_RecenterTarget; // 0x54
		public AxisState m_VerticalAxis; // 0x58
		public AxisState.Recentering m_VerticalRecentering; // 0xB0
		public AxisState m_HorizontalAxis; // 0xD0
		public AxisState.Recentering m_HorizontalRecentering; // 0x128

		// Properties
		public override bool IsValid { get; } // 0x004D5AB0-0x004D5B00
		public override CinemachineCore.Stage Stage { get; } // 0x004D5B00-0x004D5B10

		// Nested types
		public enum RecenterTargetMode // TypeDefIndex: 2634
		{
			None = 0,
			FollowTargetForward = 1,
			LookAtTargetForward = 2
		}

		// Constructors
		public CinemachinePOV(); // 0x004D7960-0x004D7B60

		// Methods
		private void OnValidate(); // 0x004D5B10-0x004D5C20
		public override void PrePipelineMutateCameraState(ref CameraState curState, float deltaTime); // 0x004D5C20-0x004D5C30
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x004D6810-0x004D6820
		private void ApplyPOV(ref CameraState curState, float deltaTime); // 0x004D5C30-0x004D6260
		public Vector2 GetRecenterTarget(); // 0x004D6260-0x004D6810
		public override bool OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime, ref CinemachineVirtualCameraBase.TransitionParams transitionParams); // 0x004D6820-0x004D7960
	}

	public class CinemachineSameAsFollowTarget : CinemachineComponentBase // TypeDefIndex: 2635
	{
		// Fields
		[FormerlySerializedAs] // 0x00253500-0x00253520
		public float m_Damping; // 0x50
		private Quaternion m_PreviousReferenceOrientation; // 0x54

		// Properties
		public override bool IsValid { get; } // 0x004DC8A0-0x004DC9E0
		public override CinemachineCore.Stage Stage { get; } // 0x004DC9E0-0x004DC9F0

		// Constructors
		public CinemachineSameAsFollowTarget(); // 0x004DCB10-0x004DCBE0

		// Methods
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x004DC9F0-0x004DCB10
	}

	public class CinemachineTrackedDolly : CinemachineComponentBase // TypeDefIndex: 2636
	{
		// Fields
		public CinemachinePathBase m_Path; // 0x50
		public float m_PathPosition; // 0x58
		public CinemachinePathBase.PositionUnits m_PositionUnits; // 0x5C
		public Vector3 m_PathOffset; // 0x60
		public float m_XDamping; // 0x6C
		public float m_YDamping; // 0x70
		public float m_ZDamping; // 0x74
		public CameraUpMode m_CameraUp; // 0x78
		public float m_PitchDamping; // 0x7C
		public float m_YawDamping; // 0x80
		public float m_RollDamping; // 0x84
		public AutoDolly m_AutoDolly; // 0x88
		private float m_PreviousPathPosition; // 0x98
		private Quaternion m_PreviousOrientation; // 0x9C
		private Vector3 m_PreviousCameraPosition; // 0xAC

		// Properties
		public override bool IsValid { get; } // 0x004E7520-0x004E7650
		public override CinemachineCore.Stage Stage { get; } // 0x004E7650-0x004E7660
		private Vector3 AngularDamping { get; } // 0x004E9140-0x004E9200

		// Nested types
		public enum CameraUpMode // TypeDefIndex: 2637
		{
			Default = 0,
			Path = 1,
			PathNoRoll = 2,
			FollowTarget = 3,
			FollowTargetNoRoll = 4
		}

		[Serializable]
		public struct AutoDolly // TypeDefIndex: 2638
		{
			// Fields
			public bool m_Enabled; // 0x00
			public float m_PositionOffset; // 0x04
			public int m_SearchRadius; // 0x08
			[FormerlySerializedAs] // 0x00253520-0x00253540
			public int m_SearchResolution; // 0x0C

			// Constructors
			public AutoDolly(bool enabled, float positionOffset, int searchRadius, int stepsPerSegment); // 0x00280A20-0x00280A80
		}

		// Constructors
		public CinemachineTrackedDolly(); // 0x004E9200-0x004E93D0

		// Methods
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x004E7660-0x004E8AA0
		private Quaternion GetCameraOrientationAtPathPoint(Quaternion pathOrientation, Vector3 up); // 0x004E8AA0-0x004E9140
	}

	public class CinemachineTransposer : CinemachineComponentBase // TypeDefIndex: 2639
	{
		// Fields
		public BindingMode m_BindingMode; // 0x50
		public Vector3 m_FollowOffset; // 0x54
		public float m_XDamping; // 0x60
		public float m_YDamping; // 0x64
		public float m_ZDamping; // 0x68
		public AngularDampingMode m_AngularDampingMode; // 0x6C
		public float m_PitchDamping; // 0x70
		public float m_YawDamping; // 0x74
		public float m_RollDamping; // 0x78
		public float m_AngularDamping; // 0x7C
		private bool <HideOffsetInInspector>k__BackingField; // 0x80
		private Vector3 m_PreviousTargetPosition; // 0x84
		private Quaternion m_PreviousReferenceOrientation; // 0x90
		private Quaternion m_targetOrientationOnAssign; // 0xA0
		private Transform m_previousTarget; // 0xB0

		// Properties
		public bool HideOffsetInInspector { get; set; } // 0x004E93D0-0x004E93E0 0x004E93E0-0x004E93F0
		public Vector3 EffectiveOffset { get; } // 0x004D2EC0-0x004D2F40
		public override bool IsValid { get; } // 0x004E93F0-0x004E9530
		public override CinemachineCore.Stage Stage { get; } // 0x004E9530-0x004E9540
		protected Vector3 Damping { get; } // 0x004E9B30-0x004E9B60
		protected Vector3 AngularDamping { get; } // 0x004E9A50-0x004E9B30

		// Nested types
		public enum BindingMode // TypeDefIndex: 2640
		{
			LockToTargetOnAssign = 0,
			LockToTargetWithWorldUp = 1,
			LockToTargetNoRoll = 2,
			LockToTarget = 3,
			WorldSpace = 4,
			SimpleFollowWithWorldUp = 5
		}

		public enum AngularDampingMode // TypeDefIndex: 2641
		{
			Euler = 0,
			Quaternion = 1
		}

		// Constructors
		public CinemachineTransposer(); // 0x004D5870-0x004D5AB0

		// Methods
		protected virtual void OnValidate(); // 0x004D28C0-0x004D2950
		public override void MutateCameraState(ref CameraState curState, float deltaTime); // 0x004E9540-0x004E9A50
		public override void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x004D2C40-0x004D2D50
		protected void InitPrevFrameStateInfo(ref CameraState curState, float deltaTime); // 0x004D3EA0-0x004D4130
		protected void TrackTarget(float deltaTime, Vector3 up, Vector3 desiredCameraOffset, out Vector3 outTargetPosition, out Quaternion outTargetOrient); // 0x004D4130-0x004D4DC0
		public virtual Vector3 GetTargetCameraPosition(Vector3 worldUp); // 0x004E9B60-0x004E9E90
		public Quaternion GetReferenceOrientation(Vector3 worldUp); // 0x004C9DD0-0x004CA6C0
	}

	[Serializable]
	public struct AxisState // TypeDefIndex: 2642
	{
		// Fields
		public float Value; // 0x00
		public SpeedMode m_SpeedMode; // 0x04
		public float m_MaxSpeed; // 0x08
		public float m_AccelTime; // 0x0C
		public float m_DecelTime; // 0x10
		[FormerlySerializedAs] // 0x00253540-0x00253560
		public string m_InputAxisName; // 0x18
		public float m_InputAxisValue; // 0x20
		[FormerlySerializedAs] // 0x00253560-0x00253580
		public bool m_InvertInput; // 0x24
		public float m_MinValue; // 0x28
		public float m_MaxValue; // 0x2C
		public bool m_Wrap; // 0x30
		public Recentering m_Recentering; // 0x34
		private float mCurrentSpeed; // 0x50
		private const float Epsilon = 0.0001f; // Metadata: 0x0015A893
		private bool <ValueRangeLocked>k__BackingField; // 0x54
		private bool <HasRecentering>k__BackingField; // 0x55

		// Properties
		public bool ValueRangeLocked { set; } // 0x00267790-0x002677A0
		public bool HasRecentering { set; } // 0x002677A0-0x00267800

		// Nested types
		public enum SpeedMode // TypeDefIndex: 2643
		{
			MaxSpeed = 0,
			InputValueGain = 1
		}

		[Serializable]
		public struct Recentering // TypeDefIndex: 2644
		{
			// Fields
			public bool m_enabled; // 0x00
			public float m_WaitTime; // 0x04
			public float m_RecenteringTime; // 0x08
			private float mLastAxisInputTime; // 0x0C
			private float mRecenteringVelocity; // 0x10
			[FormerlySerializedAs] // 0x00253580-0x002535A0
			[SerializeField] // 0x00253580-0x002535A0
			private int m_LegacyHeadingDefinition; // 0x14
			[FormerlySerializedAs] // 0x002535A0-0x002535C0
			[SerializeField] // 0x002535A0-0x002535C0
			private int m_LegacyVelocityFilterStrength; // 0x18

			// Constructors
			public Recentering(bool enabled, float waitTime, float recenteringTime); // 0x002803B0-0x002803D0

			// Methods
			public void Validate(); // 0x002803D0-0x00280450
			public void CancelRecentering(); // 0x00280450-0x002804A0
			public void DoRecentering(ref AxisState axis, float deltaTime, float recenterTarget); // 0x002804A0-0x002804B0
			internal bool LegacyUpgrade(ref int heading, ref int velocityFilter); // 0x002804B0-0x002804E0
		}

		// Constructors
		public AxisState(float minValue, float maxValue, bool wrap, bool rangeLocked, float maxSpeed, float accelTime, float decelTime, string name, bool invert); // 0x002675E0-0x00267660

		// Methods
		public void Validate(); // 0x00267660-0x00267670
		public void Reset(); // 0x00267670-0x00267680
		public bool Update(float deltaTime); // 0x00267680-0x00267690
		private float ClampValue(float v); // 0x00267690-0x00267770
		private bool MaxSpeedUpdate(float input, float deltaTime); // 0x00267770-0x00267780
		private float GetMaxSpeed(); // 0x00267780-0x00267790
	}

	public struct CameraState // TypeDefIndex: 2645
	{
		// Fields
		private LensSettings <Lens>k__BackingField; // 0x00
		private Vector3 <ReferenceUp>k__BackingField; // 0x2C
		private Vector3 <ReferenceLookAt>k__BackingField; // 0x38
		public static Vector3 kNoPoint; // 0x00
		private Vector3 <RawPosition>k__BackingField; // 0x44
		private Quaternion <RawOrientation>k__BackingField; // 0x50
		private Vector3 <PositionDampingBypass>k__BackingField; // 0x60
		private float <ShotQuality>k__BackingField; // 0x6C
		private Vector3 <PositionCorrection>k__BackingField; // 0x70
		private Quaternion <OrientationCorrection>k__BackingField; // 0x7C
		private BlendHintValue <BlendHint>k__BackingField; // 0x8C
		private CustomBlendable mCustom0; // 0x90
		private CustomBlendable mCustom1; // 0xA0
		private CustomBlendable mCustom2; // 0xB0
		private CustomBlendable mCustom3; // 0xC0
		private List<CustomBlendable> m_CustomOverflow; // 0xD0
		private int <NumCustomBlendables>k__BackingField; // 0xD8

		// Properties
		public LensSettings Lens { get; set; } // 0x00267800-0x00267820 0x00267820-0x00267840
		public Vector3 ReferenceUp { get; set; } // 0x00267840-0x00267850 0x00267850-0x00267860
		public Vector3 ReferenceLookAt { get; set; } // 0x00267860-0x00267870 0x00267870-0x00267880
		public bool HasLookAt { get; } // 0x00267880-0x00267920
		public Vector3 RawPosition { get; set; } // 0x00267920-0x00267930 0x00267930-0x00267940
		public Quaternion RawOrientation { get; set; } // 0x00267940-0x00267950 0x00267950-0x00267960
		public Vector3 PositionDampingBypass { get; set; } // 0x00267960-0x00267970 0x00267970-0x00267980
		public float ShotQuality { get; set; } // 0x00267980-0x00267990 0x00267990-0x002679A0
		public Vector3 PositionCorrection { get; set; } // 0x002679A0-0x002679C0 0x002679C0-0x002679D0
		public Quaternion OrientationCorrection { get; set; } // 0x002679D0-0x002679F0 0x002679F0-0x00267A00
		public Vector3 CorrectedPosition { get; } // 0x00267A00-0x00267AA0
		public Quaternion CorrectedOrientation { get; } // 0x00267AA0-0x00267BF0
		public Vector3 FinalPosition { get; } // 0x00267BF0-0x00267C90
		public Quaternion FinalOrientation { get; } // 0x00267C90-0x00267CA0
		public BlendHintValue BlendHint { get; set; } // 0x00267CA0-0x00267CB0 0x00267CB0-0x00267CC0
		public static CameraState Default { get; } // 0x0067E2F0-0x0067E6D0
		public int NumCustomBlendables { get; private set; } // 0x00267CC0-0x00267CD0 0x00267CD0-0x00267CE0

		// Nested types
		public enum BlendHintValue // TypeDefIndex: 2646
		{
			Nothing = 0,
			NoPosition = 1,
			NoOrientation = 2,
			NoTransform = 3,
			SphericalPositionBlend = 4,
			CylindricalPositionBlend = 8,
			RadialAimBlend = 16,
			IgnoreLookAtTarget = 32,
			NoLens = 64
		}

		public struct CustomBlendable // TypeDefIndex: 2647
		{
			// Fields
			public UnityEngine.Object m_Custom; // 0x00
			public float m_Weight; // 0x08

			// Constructors
			public CustomBlendable(UnityEngine.Object custom, float weight); // 0x002804E0-0x002805F0
		}

		// Constructors
		static CameraState(); // 0x006820A0-0x006820E0

		// Methods
		public CustomBlendable GetCustomBlendable(int index); // 0x00267CE0-0x00267CF0
		private int FindCustomBlendable(UnityEngine.Object custom); // 0x00267CF0-0x00267D00
		public void AddCustomBlendable(CustomBlendable b); // 0x00267D00-0x00267D10
		public static CameraState Lerp(CameraState stateA, CameraState stateB, float t); // 0x0067E840-0x00680950
		private static float InterpolateFOV(float fovA, float fovB, float dA, float dB, float t); // 0x00680950-0x00681880
		private static Vector3 ApplyPosBlendHint(Vector3 posA, BlendHintValue hintA, Vector3 posB, BlendHintValue hintB, Vector3 original, Vector3 blended); // 0x00682040-0x00682070
		private static Quaternion ApplyRotBlendHint(Quaternion rotA, BlendHintValue hintA, Quaternion rotB, BlendHintValue hintB, Quaternion original, Quaternion blended); // 0x00682070-0x006820A0
		private Vector3 InterpolatePosition(Vector3 posA, Vector3 pivotA, Vector3 posB, Vector3 pivotB, float t); // 0x00267D10-0x00267D20
	}

	public class CinemachineBlend // TypeDefIndex: 2648
	{
		// Fields
		private ICinemachineCamera <CamA>k__BackingField; // 0x10
		private ICinemachineCamera <CamB>k__BackingField; // 0x18
		private AnimationCurve <BlendCurve>k__BackingField; // 0x20
		private float <TimeInBlend>k__BackingField; // 0x28
		private float <Duration>k__BackingField; // 0x2C

		// Properties
		public ICinemachineCamera CamA { get; set; } // 0x00683280-0x00683290 0x00683290-0x006832A0
		public ICinemachineCamera CamB { get; set; } // 0x006832A0-0x006832B0 0x006832B0-0x006832C0
		public AnimationCurve BlendCurve { get; set; } // 0x006832C0-0x006832D0 0x006832D0-0x006832E0
		public float TimeInBlend { get; set; } // 0x006832E0-0x006832F0 0x006832F0-0x00683300
		public float BlendWeight { get; } // 0x0067E6D0-0x0067E840
		public bool IsValid { get; } // 0x0067DA90-0x0067DBC0
		public float Duration { get; set; } // 0x00683320-0x00683330 0x00683330-0x00683340
		public bool IsComplete { get; } // 0x00683300-0x00683320
		public string Description { get; } // 0x00683340-0x006836A0
		public CameraState State { get; } // 0x0067DEC0-0x0067E2F0

		// Constructors
		public CinemachineBlend(ICinemachineCamera a, ICinemachineCamera b, AnimationCurve curve, float duration, float t); // 0x006838F0-0x00684270

		// Methods
		public bool Uses(ICinemachineCamera cam); // 0x00683800-0x006838F0
		public void UpdateCameraState(Vector3 worldUp, float deltaTime); // 0x0067DC50-0x0067DEC0
	}

	[Serializable]
	public struct CinemachineBlendDefinition // TypeDefIndex: 2649
	{
		// Fields
		public Style m_Style; // 0x00
		public float m_Time; // 0x04
		public AnimationCurve m_CustomCurve; // 0x08
		private static AnimationCurve[] sStandardCurves; // 0x00

		// Properties
		public AnimationCurve BlendCurve { get; } // 0x00267D50-0x00267D60

		// Nested types
		public enum Style // TypeDefIndex: 2650
		{
			Cut = 0,
			EaseInOut = 1,
			EaseIn = 2,
			EaseOut = 3,
			HardIn = 4,
			HardOut = 5,
			Linear = 6,
			Custom = 7
		}

		// Constructors
		public CinemachineBlendDefinition(Style style, float time); // 0x00267D20-0x00267D40

		// Methods
		private void CreateStandardCurves(); // 0x00267D40-0x00267D50
	}

	internal class StaticPointVirtualCamera : ICinemachineCamera // TypeDefIndex: 2651
	{
		// Fields
		private string <Name>k__BackingField; // 0x10
		private int <Priority>k__BackingField; // 0x18
		private Transform <LookAt>k__BackingField; // 0x20
		private Transform <Follow>k__BackingField; // 0x28
		private CameraState <State>k__BackingField; // 0x30

		// Properties
		public string Name { get; private set; } // 0x00AAEE20-0x00AAEE30 0x00AAEE30-0x00AAEE40
		public int Priority { get; } // 0x00AAEE40-0x00AAEE50
		public Transform LookAt { get; } // 0x00AAEE50-0x00AAEE60
		public Transform Follow { get; } // 0x00AAEE60-0x00AAEE70
		public CameraState State { get; private set; } // 0x00AAEE70-0x00AAEE90 0x00AAEE90-0x00AAEEB0
		public GameObject VirtualCameraGameObject { get; } // 0x00AAEEB0-0x00AAEEC0
		public bool IsValid { get; } // 0x00AAEEC0-0x00AAEED0
		public ICinemachineCamera ParentCamera { get; } // 0x00AAEED0-0x00AAEEE0

		// Constructors
		public StaticPointVirtualCamera(CameraState state, string name); // 0x00AAEDF0-0x00AAEE20

		// Methods
		public bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A8E3 */); // 0x00AAEEE0-0x00AAEEF0
		public void UpdateCameraState(Vector3 worldUp, float deltaTime); // 0x00AAEEF0-0x00AAEF00
		public void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x00AAEF00-0x00AAEF10
	}

	internal class BlendSourceVirtualCamera : ICinemachineCamera // TypeDefIndex: 2652
	{
		// Fields
		private CinemachineBlend <Blend>k__BackingField; // 0x10
		private int <Priority>k__BackingField; // 0x18
		private Transform <LookAt>k__BackingField; // 0x20
		private Transform <Follow>k__BackingField; // 0x28
		private CameraState <State>k__BackingField; // 0x30

		// Properties
		public CinemachineBlend Blend { get; set; } // 0x0067D9B0-0x0067D9C0 0x0067D9C0-0x0067D9D0
		public string Name { get; } // 0x0067D9D0-0x0067DA00
		public int Priority { get; } // 0x0067DA00-0x0067DA10
		public Transform LookAt { get; } // 0x0067DA10-0x0067DA20
		public Transform Follow { get; } // 0x0067DA20-0x0067DA30
		public CameraState State { get; private set; } // 0x0067DA30-0x0067DA50 0x0067DA50-0x0067DA70
		public GameObject VirtualCameraGameObject { get; } // 0x0067DA70-0x0067DA80
		public bool IsValid { get; } // 0x0067DA80-0x0067DA90
		public ICinemachineCamera ParentCamera { get; } // 0x0067DBC0-0x0067DBD0

		// Constructors
		public BlendSourceVirtualCamera(CinemachineBlend blend); // 0x0067D9A0-0x0067D9B0

		// Methods
		public bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A8E4 */); // 0x0067DBD0-0x0067DBF0
		public void UpdateCameraState(Vector3 worldUp, float deltaTime); // 0x0067DBF0-0x0067DC50
		public void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x00681880-0x00682040
	}

	[Serializable]
	public sealed class CinemachineBlenderSettings : ScriptableObject // TypeDefIndex: 2653
	{
		// Fields
		public CustomBlend[] m_CustomBlends; // 0x18
		public const string kBlendFromAnyCameraLabel = "**ANY CAMERA**"; // Metadata: 0x0015A8E5

		// Nested types
		[Serializable]
		public struct CustomBlend // TypeDefIndex: 2654
		{
			// Fields
			public string m_From; // 0x00
			public string m_To; // 0x08
			public CinemachineBlendDefinition m_Blend; // 0x10
		}

		// Constructors
		public CinemachineBlenderSettings(); // 0x00686AA0-0x00686AB0

		// Methods
		public CinemachineBlendDefinition GetBlendForVirtualCameras(string fromCameraName, string toCameraName, CinemachineBlendDefinition defaultBlend); // 0x00686800-0x00686AA0
	}

	public abstract class CinemachineComponentBase : MonoBehaviour // TypeDefIndex: 2655
	{
		// Fields
		protected const float Epsilon = 0.0001f; // Metadata: 0x0015A8F7
		private CinemachineVirtualCameraBase m_vcamOwner; // 0x18
		private Transform mCachedFollowTarget; // 0x20
		private CinemachineVirtualCameraBase mCachedFollowTargetVcam; // 0x28
		private ICinemachineTargetGroup mCachedFollowTargetGroup; // 0x30
		private Transform mCachedLookAtTarget; // 0x38
		private CinemachineVirtualCameraBase mCachedLookAtTargetVcam; // 0x40
		private ICinemachineTargetGroup mCachedLookAtTargetGroup; // 0x48

		// Properties
		public CinemachineVirtualCameraBase VirtualCamera { get; } // 0x00697320-0x006976B0
		public Transform FollowTarget { get; } // 0x006976B0-0x006977B0
		public Transform LookAtTarget { get; } // 0x006977B0-0x006978B0
		public ICinemachineTargetGroup AbstractFollowTargetGroup { get; } // 0x006979E0-0x00697A90
		public CinemachineTargetGroup FollowTargetGroup { get; } // 0x00697A90-0x00697B90
		public Vector3 FollowTargetPosition { get; } // 0x00697B90-0x00697F80
		public Quaternion FollowTargetRotation { get; } // 0x00697F80-0x00698410
		public ICinemachineTargetGroup AbstractLookAtTargetGroup { get; } // 0x00698540-0x006985F0
		public CinemachineTargetGroup LookAtTargetGroup { get; } // 0x006985F0-0x006986F0
		public Vector3 LookAtTargetPosition { get; } // 0x006986F0-0x00698AE0
		public Quaternion LookAtTargetRotation { get; } // 0x00698AE0-0x00698E90
		public CameraState VcamState { get; } // 0x00698E90-0x00698FC0
		public abstract bool IsValid { get; }
		public abstract CinemachineCore.Stage Stage { get; }

		// Constructors
		protected CinemachineComponentBase(); // 0x00683240-0x00683280

		// Methods
		private void UpdateFollowTargetCache(); // 0x006978B0-0x006979E0
		private void UpdateLookAtTargetCache(); // 0x00698410-0x00698540
		public virtual void PrePipelineMutateCameraState(ref CameraState curState, float deltaTime); // 0x00698FC0-0x00698FD0
		public abstract void MutateCameraState(ref CameraState curState, float deltaTime);
		public virtual bool OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime, ref CinemachineVirtualCameraBase.TransitionParams transitionParams); // 0x00698FD0-0x00698FE0
		public virtual void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x00698FE0-0x00698FF0
	}

	public sealed class CinemachineCore // TypeDefIndex: 2656
	{
		// Fields
		public static readonly int kStreamingVersion; // 0x00
		public static readonly string kVersionString; // 0x08
		private static CinemachineCore sInstance; // 0x10
		public static bool sShowHiddenObjects; // 0x18
		public static AxisInputDelegate GetInputAxis; // 0x20
		public static float UniformDeltaTimeOverride; // 0x28
		public static GetBlendOverrideDelegate GetBlendOverride; // 0x30
		public static CinemachineBrain.BrainEvent CameraUpdatedEvent; // 0x38
		public static CinemachineBrain.BrainEvent CameraCutEvent; // 0x40
		private List<CinemachineBrain> mActiveBrains; // 0x10
		private List<CinemachineVirtualCameraBase> mActiveCameras; // 0x18
		private List<List<CinemachineVirtualCameraBase>> mAllCameras; // 0x20
		private CinemachineVirtualCameraBase mRoundRobinVcamLastFrame; // 0x28
		private static float mLastUpdateTime; // 0x48
		private static int <FixedFrameCount>k__BackingField; // 0x4C
		private Dictionary<CinemachineVirtualCameraBase, UpdateStatus> mUpdateStatus; // 0x30
		private UpdateFilter <CurrentUpdateFilter>k__BackingField; // 0x38

		// Properties
		public static CinemachineCore Instance { get; } // 0x00685720-0x006857F0
		public int BrainCount { get; } // 0x0069DC20-0x0069DC60
		public int VirtualCameraCount { get; } // 0x0068B690-0x0068B6D0
		private static int FixedFrameCount { get; set; } // 0x0069E130-0x0069E180 0x0069E180-0x0069E1D0
		internal UpdateFilter CurrentUpdateFilter { get; set; } // 0x0069E260-0x0069E270 0x0069E270-0x0069E280

		// Nested types
		public enum Stage // TypeDefIndex: 2657
		{
			Body = 0,
			Aim = 1,
			Noise = 2,
			Finalize = 3
		}

		public delegate float AxisInputDelegate(string axisName); // TypeDefIndex: 2658; 0x00AB43F0-0x00AB4820

		public delegate CinemachineBlendDefinition GetBlendOverrideDelegate(ICinemachineCamera fromVcam, ICinemachineCamera toVcam, CinemachineBlendDefinition defaultBlend, MonoBehaviour owner); // TypeDefIndex: 2659; 0x00AB4870-0x00AB4E60

		private class UpdateStatus // TypeDefIndex: 2660
		{
			// Fields
			public int lastUpdateFrame; // 0x10
			public int lastUpdateFixedFrame; // 0x14
			public UpdateTracker.UpdateClock lastUpdateMode; // 0x18
			public float lastUpdateDeltaTime; // 0x1C

			// Constructors
			public UpdateStatus(); // 0x00AB4F30-0x00AB4F40
		}

		internal enum UpdateFilter // TypeDefIndex: 2661
		{
			Fixed = 0,
			Late = 1,
			Smart = 8,
			SmartFixed = 8,
			SmartLate = 9
		}

		// Constructors
		public CinemachineCore(); // 0x00685EE0-0x00685F70
		static CinemachineCore(); // 0x0069ED00-0x0069EE30

		// Methods
		public CinemachineBrain GetActiveBrain(int index); // 0x0069DC60-0x0069DCB0
		internal void AddActiveBrain(CinemachineBrain brain); // 0x00687430-0x006874F0
		internal void RemoveActiveBrain(CinemachineBrain brain); // 0x006876A0-0x00687720
		public CinemachineVirtualCameraBase GetVirtualCamera(int index); // 0x0068B6D0-0x0068B720
		internal void AddActiveCamera(CinemachineVirtualCameraBase vcam); // 0x0069DCB0-0x0069DDB0
		internal void RemoveActiveCamera(CinemachineVirtualCameraBase vcam); // 0x0069DDB0-0x0069DE30
		internal void CameraAwakened(CinemachineVirtualCameraBase vcam); // 0x0069DE30-0x0069DFE0
		internal void CameraDestroyed(CinemachineVirtualCameraBase vcam); // 0x0069DFE0-0x0069E130
		internal void UpdateAllActiveVirtualCameras(int layerMask, Vector3 worldUp, float deltaTime); // 0x00687B60-0x00688280
		internal void UpdateVirtualCamera(CinemachineVirtualCameraBase vcam, Vector3 worldUp, float deltaTime); // 0x00688280-0x006887A0
		[RuntimeInitializeOnLoadMethod] // 0x002536A0-0x002536B0
		private static void InitializeModule(); // 0x0069E1D0-0x0069E260
		private static Transform GetUpdateTarget(CinemachineVirtualCameraBase vcam); // 0x006887A0-0x00688B70
		internal UpdateTracker.UpdateClock GetVcamUpdateStatus(CinemachineVirtualCameraBase vcam); // 0x0069E280-0x0069E320
		public bool IsLive(ICinemachineCamera vcam); // 0x00686DF0-0x00686FC0
		public void GenerateCameraActivationEvent(ICinemachineCamera vcam, ICinemachineCamera vcamFrom); // 0x006857F0-0x006859D0
		public void GenerateCameraCutEvent(ICinemachineCamera vcam); // 0x006859D0-0x00685C30
		public CinemachineBrain FindPotentialTargetBrain(CinemachineVirtualCameraBase vcam); // 0x0069E320-0x0069ED00
	}

	public abstract class CinemachineExtension : MonoBehaviour // TypeDefIndex: 2662
	{
		// Fields
		protected const float Epsilon = 0.0001f; // Metadata: 0x0015A91F
		private CinemachineVirtualCameraBase m_vcamOwner; // 0x18
		private Dictionary<ICinemachineCamera, object> mExtraState; // 0x20

		// Properties
		public CinemachineVirtualCameraBase VirtualCamera { get; } // 0x00695980-0x00695A80

		// Constructors
		protected CinemachineExtension(); // 0x0068C0A0-0x0068C0E0

		// Methods
		protected virtual void Awake(); // 0x0069F340-0x0069F360
		protected virtual void OnDestroy(); // 0x0068E440-0x0068E460
		protected virtual void ConnectToVcam(bool connect); // 0x0069F360-0x0069F850
		public void InvokePostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime); // 0x0069F850-0x0069F870
		protected abstract void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime);
		public virtual void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x0069F870-0x0069F880
		public virtual bool OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x0069F880-0x0069F890
		protected T GetExtraState<T>(ICinemachineCamera vcam)
			where T : class, new();
		protected List<T> GetAllExtraStates<T>()
			where T : class, new();
	}

	public abstract class CinemachinePathBase : MonoBehaviour // TypeDefIndex: 2663
	{
		// Fields
		public int m_Resolution; // 0x18
		public Appearance m_Appearance; // 0x20
		private float[] m_DistanceToPos; // 0x28
		private float[] m_PosToDistance; // 0x30
		private int m_CachedSampleSteps; // 0x38
		private float m_PathLength; // 0x3C
		private float m_cachedPosStepSize; // 0x40
		private float m_cachedDistanceStepSize; // 0x44

		// Properties
		public abstract float MinPos { get; }
		public abstract float MaxPos { get; }
		public abstract bool Looped { get; }
		public abstract int DistanceCacheSampleStepsPerSegment { get; }
		public float PathLength { get; } // 0x004D9EF0-0x004D9FB0

		// Nested types
		[Serializable]
		public class Appearance // TypeDefIndex: 2664
		{
			// Fields
			public Color pathColor; // 0x10
			public Color inactivePathColor; // 0x20
			public float width; // 0x30

			// Constructors
			public Appearance(); // 0x00AB7B60-0x00AB7B80
		}

		public enum PositionUnits // TypeDefIndex: 2665
		{
			PathUnits = 0,
			Distance = 1,
			Normalized = 2
		}

		// Constructors
		protected CinemachinePathBase(); // 0x004D9120-0x004D91B0

		// Methods
		public virtual float StandardizePos(float pos); // 0x004D91B0-0x004D92D0
		public abstract Vector3 EvaluatePosition(float pos);
		public abstract Vector3 EvaluateTangent(float pos);
		public abstract Quaternion EvaluateOrientation(float pos);
		public virtual float FindClosestPoint(Vector3 p, int startSegment, int searchRadius, int stepsPerSegment); // 0x004D92D0-0x004D99D0
		public float MinUnit(PositionUnits units); // 0x004D99D0-0x004D99F0
		public float MaxUnit(PositionUnits units); // 0x004D99F0-0x004D9AE0
		public virtual float StandardizeUnit(float pos, PositionUnits units); // 0x004D9FB0-0x004DA0D0
		public Vector3 EvaluatePositionAtUnit(float pos, PositionUnits units); // 0x004DA240-0x004DA260
		public Vector3 EvaluateTangentAtUnit(float pos, PositionUnits units); // 0x004DA670-0x004DA690
		public Quaternion EvaluateOrientationAtUnit(float pos, PositionUnits units); // 0x004DA690-0x004DA6B0
		public virtual void InvalidateDistanceCache(); // 0x004DA6B0-0x004DA6C0
		public bool DistanceCacheIsValid(); // 0x004DA6C0-0x004DA740
		public float StandardizePathDistance(float distance); // 0x004DA0D0-0x004DA240
		public float ToNativePathUnits(float pos, PositionUnits units); // 0x004DA260-0x004DA670
		public float FromPathNativeUnits(float pos, PositionUnits units); // 0x004DA740-0x004DAA50
		private void ResamplePath(int stepsPerSegment); // 0x004D9AE0-0x004D9EF0
	}

	public abstract class CinemachineVirtualCameraBase : MonoBehaviour, ICinemachineCamera // TypeDefIndex: 2666
	{
		// Fields
		[SerializeField] // 0x002535C0-0x002535D0
		public string[] m_ExcludedPropertiesInInspector; // 0x18
		[SerializeField] // 0x002535D0-0x002535E0
		public CinemachineCore.Stage[] m_LockStageInInspector; // 0x20
		private int m_ValidatingStreamVersion; // 0x28
		private bool m_OnValidateCalled; // 0x2C
		[SerializeField] // 0x002535E0-0x002535F0
		private int m_StreamingVersion; // 0x30
		public int m_Priority; // 0x34
		public StandbyUpdateMode m_StandbyUpdate; // 0x38
		private List<CinemachineExtension> mExtensions; // 0x40
		private bool <PreviousStateIsValid>k__BackingField; // 0x48
		private bool mSlaveStatusUpdated; // 0x49
		private CinemachineVirtualCameraBase m_parentVcam; // 0x50
		private int m_QueuePriority; // 0x58

		// Properties
		public int ValidatingStreamVersion { get; private set; } // 0x004EBA40-0x004EBAA0 0x004ED310-0x004ED320
		public string Name { get; } // 0x004D1300-0x004D1310
		public virtual string Description { get; } // 0x004ED4D0-0x004ED500
		public int Priority { get; set; } // 0x004ED500-0x004ED510 0x004ED510-0x004ED520
		public GameObject VirtualCameraGameObject { get; } // 0x004ED520-0x004ED640
		public bool IsValid { get; } // 0x004ED640-0x004ED720
		public abstract CameraState State { get; }
		public ICinemachineCamera ParentCamera { get; } // 0x004ED470-0x004ED4D0
		public abstract Transform LookAt { get; set; }
		public abstract Transform Follow { get; set; }
		public virtual bool PreviousStateIsValid { get; set; } // 0x004ED730-0x004ED740 0x004ED740-0x004ED750

		// Nested types
		public enum StandbyUpdateMode // TypeDefIndex: 2667
		{
			Never = 0,
			Always = 1,
			RoundRobin = 2
		}

		public enum BlendHint // TypeDefIndex: 2668
		{
			None = 0,
			SphericalPosition = 1,
			CylindricalPosition = 2,
			ScreenSpaceAimWhenTargetsDiffer = 3
		}

		[Serializable]
		public struct TransitionParams // TypeDefIndex: 2669
		{
			// Fields
			[FormerlySerializedAs] // 0x002535F0-0x00253610
			public BlendHint m_BlendHint; // 0x00
			public bool m_InheritPosition; // 0x04
			public CinemachineBrain.VcamActivatedEvent m_OnCameraLive; // 0x08
		}

		// Constructors
		protected CinemachineVirtualCameraBase(); // 0x004CBB20-0x004CBC70

		// Methods
		public virtual void AddExtension(CinemachineExtension extension); // 0x004ED320-0x004ED3F0
		public virtual void RemoveExtension(CinemachineExtension extension); // 0x004ED3F0-0x004ED470
		protected void InvokePostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState newState, float deltaTime); // 0x004C6280-0x004C65E0
		protected bool InvokeOnTransitionInExtensions(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x004C83B0-0x004C85D0
		protected void ApplyPositionBlendMethod(ref CameraState state, BlendHint hint); // 0x004C7C80-0x004C7CA0
		public virtual bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A92F */); // 0x004ED720-0x004ED730
		public void UpdateCameraState(Vector3 worldUp, float deltaTime); // 0x004CA780-0x004CA810
		public abstract void InternalUpdateCameraState(Vector3 worldUp, float deltaTime);
		public virtual void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime); // 0x004CA6C0-0x004CA780
		protected virtual void OnDestroy(); // 0x004C5090-0x004C5160
		protected virtual void OnTransformParentChanged(); // 0x004ED750-0x004ED7D0
		protected virtual void OnValidate(); // 0x004C0F40-0x004C0FA0
		protected virtual void OnEnable(); // 0x004C45C0-0x004C48C0
		protected virtual void OnDisable(); // 0x004E1070-0x004E10D0
		protected virtual void Update(); // 0x004ED7D0-0x004ED7E0
		private void UpdateSlaveStatus(); // 0x004C48C0-0x004C4A60
		protected Transform ResolveLookAt(Transform localLookAt); // 0x004C5240-0x004C5450
		protected Transform ResolveFollow(Transform localFollow); // 0x004C5470-0x004C5680
		private void UpdateVcamPoolStatus(); // 0x004C4A60-0x004C4C60
		public void MoveToTopOfPrioritySubqueue(); // 0x004ED7E0-0x004ED7F0
		public virtual void OnTargetObjectWarped(Transform target, Vector3 positionDelta); // 0x004C58A0-0x004C5940
		protected CinemachineBlend CreateBlend(ICinemachineCamera camA, ICinemachineCamera camB, CinemachineBlendDefinition blendDef, CinemachineBlend activeBlend); // 0x004E09A0-0x004E0AD0
		protected CameraState PullStateFromVirtualCamera(Vector3 worldUp, ref LensSettings lens); // 0x004C7820-0x004C7C80
	}

	public interface ICinemachineCamera // TypeDefIndex: 2670
	{
		// Properties
		string Name { get; }
		int Priority { get; }
		Transform LookAt { get; }
		Transform Follow { get; }
		CameraState State { get; }
		GameObject VirtualCameraGameObject { get; }
		bool IsValid { get; }
		ICinemachineCamera ParentCamera { get; }

		// Methods
		bool IsLiveChild(ICinemachineCamera vcam, bool dominantChildOnly = false /* Metadata: 0x0015A94C */);
		void UpdateCameraState(Vector3 worldUp, float deltaTime);
		void OnTransitionFromCamera(ICinemachineCamera fromCam, Vector3 worldUp, float deltaTime);
	}

	[Serializable]
	public struct LensSettings // TypeDefIndex: 2671
	{
		// Fields
		public static LensSettings Default; // 0x00
		public float FieldOfView; // 0x00
		public float OrthographicSize; // 0x04
		public float NearClipPlane; // 0x08
		public float FarClipPlane; // 0x0C
		public float Dutch; // 0x10
		private bool <Orthographic>k__BackingField; // 0x14
		private Vector2 <SensorSize>k__BackingField; // 0x18
		private bool <IsPhysicalCamera>k__BackingField; // 0x20
		public Vector2 LensShift; // 0x24

		// Properties
		public bool Orthographic { get; set; } // 0x002801C0-0x002801D0 0x002801D0-0x002801E0
		public Vector2 SensorSize { get; set; } // 0x002801E0-0x002801F0 0x002801F0-0x00280200
		public float Aspect { get; } // 0x00280200-0x00280230
		public bool IsPhysicalCamera { get; set; } // 0x00280230-0x00280240 0x00280240-0x00280250

		// Constructors
		public LensSettings(float fov, float orthographicSize, float nearClip, float farClip, float dutch); // 0x00280260-0x00280290
		static LensSettings(); // 0x00AABFD0-0x00AAC020

		// Methods
		public static LensSettings FromCamera(Camera fromCamera); // 0x00AAB300-0x00AAB870
		public void SnapshotCameraReadOnlyProperties(Camera camera); // 0x00280250-0x00280260
		public static LensSettings Lerp(LensSettings lensA, LensSettings lensB, float t); // 0x00AAB870-0x00AABFD0
		public void Validate(); // 0x00280290-0x002803B0
	}

	public sealed class NoiseSettings : SignalSourceAsset // TypeDefIndex: 2672
	{
		// Fields
		[FormerlySerializedAs] // 0x00253610-0x00253630
		public TransformNoiseParams[] PositionNoise; // 0x18
		[FormerlySerializedAs] // 0x00253630-0x00253650
		public TransformNoiseParams[] OrientationNoise; // 0x20

		// Properties
		public override float SignalDuration { get; } // 0x00AAC370-0x00AAC380

		// Nested types
		[Serializable]
		public struct NoiseParams // TypeDefIndex: 2673
		{
			// Fields
			public float Frequency; // 0x00
			public float Amplitude; // 0x04
			public bool Constant; // 0x08

			// Methods
			public float GetValueAt(float time, float timeOffset); // 0x00280B90-0x00280C50
		}

		[Serializable]
		public struct TransformNoiseParams // TypeDefIndex: 2674
		{
			// Fields
			public NoiseParams X; // 0x00
			public NoiseParams Y; // 0x0C
			public NoiseParams Z; // 0x18

			// Methods
			public Vector3 GetValueAt(float time, Vector3 timeOffsets); // 0x00280C50-0x00280D10
		}

		// Constructors
		public NoiseSettings(); // 0x00AAC4F0-0x00AAC540

		// Methods
		public static Vector3 GetCombinedFilterResults(TransformNoiseParams[] noiseParams, float time, Vector3 timeOffsets); // 0x00AAC020-0x00AAC370
		public override void GetSignal(float timeSinceSignalStart, out Vector3 pos, out Quaternion rot); // 0x00AAC380-0x00AAC4F0
	}

	public static class RuntimeUtility // TypeDefIndex: 2675
	{
		// Methods
		public static void DestroyObject(UnityEngine.Object obj); // 0x00AAD060-0x00AAD160
	}

	public interface ISignalSource6D // TypeDefIndex: 2676
	{
		// Methods
		void GetSignal(float timeSinceSignalStart, out Vector3 pos, out Quaternion rot);
	}

	public abstract class SignalSourceAsset : ScriptableObject, ISignalSource6D // TypeDefIndex: 2677
	{
		// Properties
		public abstract float SignalDuration { get; }

		// Constructors
		protected SignalSourceAsset(); // 0x00AAC540-0x00AAC550

		// Methods
		public abstract void GetSignal(float timeSinceSignalStart, out Vector3 pos, out Quaternion rot);
	}

	internal class UpdateTracker // TypeDefIndex: 2678
	{
		// Fields
		private static Dictionary<Transform, UpdateStatus> mUpdateStatus; // 0x00
		private static List<Transform> sToDelete; // 0x08
		private static float mLastUpdateTime; // 0x10

		// Nested types
		public enum UpdateClock // TypeDefIndex: 2679
		{
			Fixed = 0,
			Late = 1
		}

		private class UpdateStatus // TypeDefIndex: 2680
		{
			// Fields
			private int windowStart; // 0x10
			private int numWindowLateUpdateMoves; // 0x14
			private int numWindowFixedUpdateMoves; // 0x18
			private int numWindows; // 0x1C
			private int lastFrameUpdated; // 0x20
			private Matrix4x4 lastPos; // 0x24
			private UpdateClock <PreferredUpdate>k__BackingField; // 0x64

			// Properties
			public UpdateClock PreferredUpdate { get; private set; } // 0x00AB98D0-0x00AB98E0 0x00AB98E0-0x00AB98F0

			// Constructors
			public UpdateStatus(int currentFrame, Matrix4x4 pos); // 0x00AB20C0-0x00AB2150

			// Methods
			public void OnUpdate(int currentFrame, UpdateClock currentClock, Matrix4x4 pos); // 0x00AB1B70-0x00AB1D30
		}

		// Constructors
		public UpdateTracker(); // 0x00AB2250-0x00AB2260
		static UpdateTracker(); // 0x00AB2260-0x00AB28B0

		// Methods
		[RuntimeInitializeOnLoadMethod] // 0x002536B0-0x002536C0
		private static void InitializeModule(); // 0x00AB1490-0x00AB14F0
		private static void UpdateTargets(UpdateClock currentClock); // 0x00AB14F0-0x00AB1B70
		public static UpdateClock GetPreferredUpdate(Transform target); // 0x00AB1D30-0x00AB20C0
		public static void OnUpdate(UpdateClock currentClock); // 0x00AB2150-0x00AB2250
	}

	public class CinemachineTriggerAction : MonoBehaviour // TypeDefIndex: 2681
	{
		// Fields
		public LayerMask m_LayerMask; // 0x18
		public string m_WithTag; // 0x20
		public string m_WithoutTag; // 0x28
		public int m_SkipFirst; // 0x30
		public bool m_Repeating; // 0x34
		public ActionSettings m_OnObjectEnter; // 0x38
		public ActionSettings m_OnObjectExit; // 0x60
		private HashSet<GameObject> m_ActiveTriggerObjects; // 0x88

		// Nested types
		[Serializable]
		public struct ActionSettings // TypeDefIndex: 2682
		{
			// Fields
			public Mode m_Action; // 0x00
			public UnityEngine.Object m_Target; // 0x08
			public int m_BoostAmount; // 0x10
			public float m_StartTime; // 0x14
			public TimeMode m_Mode; // 0x18
			public TriggerEvent m_Event; // 0x20

			// Nested types
			public enum Mode // TypeDefIndex: 2683
			{
				Custom = 0,
				PriorityBoost = 1,
				Activate = 2,
				Deactivate = 3,
				Enable = 4,
				Disable = 5,
				Play = 6,
				Stop = 7
			}

			[Serializable]
			public class TriggerEvent : UnityEvent // TypeDefIndex: 2684
			{
				// Constructors
				public TriggerEvent(); // 0x00AB80A0-0x00AB8E10
			}

			public enum TimeMode // TypeDefIndex: 2685
			{
				FromStart = 0,
				FromEnd = 1,
				BeforeNow = 2,
				AfterNow = 3
			}

			// Constructors
			public ActionSettings(Mode action); // 0x00280A80-0x00280AE0

			// Methods
			public void Invoke(); // 0x00280AE0-0x00280B90
		}

		// Constructors
		public CinemachineTriggerAction(); // 0x004EA5D0-0x004EA7A0

		// Methods
		private bool Filter(GameObject other); // 0x004E9E90-0x004E9FE0
		private void InternalDoTriggerEnter(GameObject other); // 0x004E9FE0-0x004EA080
		private void InternalDoTriggerExit(GameObject other); // 0x004EA080-0x004EA150
		private void OnTriggerEnter(Collider other); // 0x004EA150-0x004EA240
		private void OnTriggerExit(Collider other); // 0x004EA240-0x004EA2B0
		private void OnCollisionEnter(Collision other); // 0x004EA2B0-0x004EA360
		private void OnCollisionExit(Collision other); // 0x004EA360-0x004EA390
		private void OnTriggerEnter2D(Collider2D other); // 0x004EA390-0x004EA480
		private void OnTriggerExit2D(Collider2D other); // 0x004EA480-0x004EA4F0
		private void OnCollisionEnter2D(Collision2D other); // 0x004EA4F0-0x004EA5A0
		private void OnCollisionExit2D(Collision2D other); // 0x004EA5A0-0x004EA5D0
	}

	public class CinemachineCollisionImpulseSource : CinemachineImpulseSource // TypeDefIndex: 2686
	{
		// Fields
		public LayerMask m_LayerMask; // 0x20
		public string m_IgnoreTag; // 0x28
		public bool m_UseImpactDirection; // 0x30
		public bool m_ScaleImpactWithMass; // 0x31
		public bool m_ScaleImpactWithSpeed; // 0x32
		private Rigidbody mRigidBody; // 0x38
		private Rigidbody2D mRigidBody2D; // 0x40

		// Constructors
		public CinemachineCollisionImpulseSource(); // 0x006972D0-0x00697320

		// Methods
		private void Start(); // 0x00695B50-0x00695BA0
		private void OnCollisionEnter(Collision c); // 0x00695BA0-0x00695BC0
		private void OnTriggerEnter(Collider c); // 0x00696660-0x00696710
		private float GetMassAndVelocity(Collider other, ref Vector3 vel); // 0x00696010-0x00696660
		private void GenerateImpactEvent(Collider other, Vector3 vel); // 0x00695BC0-0x00696010
		private void OnCollisionEnter2D(Collision2D c); // 0x00696710-0x00696790
		private void OnTriggerEnter2D(Collider2D c); // 0x00697220-0x006972D0
		private float GetMassAndVelocity2D(Collider2D other2d, ref Vector3 vel); // 0x00696BE0-0x00697220
		private void GenerateImpactEvent2D(Collider2D other2d, Vector3 vel); // 0x00696790-0x00696BE0
	}

	public class CinemachineFixedSignal : SignalSourceAsset // TypeDefIndex: 2687
	{
		// Fields
		public AnimationCurve m_XCurve; // 0x18
		public AnimationCurve m_YCurve; // 0x20
		public AnimationCurve m_ZCurve; // 0x28

		// Properties
		public override float SignalDuration { get; } // 0x006A0400-0x006A0490

		// Constructors
		public CinemachineFixedSignal(); // 0x006A08E0-0x006A08F0

		// Methods
		private float AxisDuration(AnimationCurve axis); // 0x006A0490-0x006A05D0
		public override void GetSignal(float timeSinceSignalStart, out Vector3 pos, out Quaternion rot); // 0x006A05D0-0x006A0840
		private float AxisValue(AnimationCurve axis, float time); // 0x006A0840-0x006A08E0
	}

	[Serializable]
	public class CinemachineImpulseDefinition // TypeDefIndex: 2688
	{
		// Fields
		public int m_ImpulseChannel; // 0x10
		public SignalSourceAsset m_RawSignal; // 0x18
		public float m_AmplitudeGain; // 0x20
		public float m_FrequencyGain; // 0x24
		public RepeatMode m_RepeatMode; // 0x28
		public bool m_Randomize; // 0x2C
		public CinemachineImpulseManager.EnvelopeDefinition m_TimeEnvelope; // 0x30
		public float m_ImpactRadius; // 0x50
		public CinemachineImpulseManager.ImpulseEvent.DirectionMode m_DirectionMode; // 0x54
		public CinemachineImpulseManager.ImpulseEvent.DissipationMode m_DissipationMode; // 0x58
		public float m_DissipationDistance; // 0x5C

		// Nested types
		public enum RepeatMode // TypeDefIndex: 2689
		{
			Stretch = 0,
			Loop = 1
		}

		private class SignalSource : ISignalSource6D // TypeDefIndex: 2690
		{
			// Fields
			private CinemachineImpulseDefinition m_Def; // 0x10
			private Vector3 m_Velocity; // 0x18
			private float m_StartTimeOffset; // 0x24

			// Properties
			public float SignalDuration { get; } // 0x00AB5CA0-0x00AB5CD0

			// Constructors
			public SignalSource(CinemachineImpulseDefinition def, Vector3 velocity); // 0x00AB5C00-0x00AB5CA0

			// Methods
			public void GetSignal(float timeSinceSignalStart, out Vector3 pos, out Quaternion rot); // 0x00AB5CD0-0x00AB6190
		}

		// Constructors
		public CinemachineImpulseDefinition(); // 0x004CEEF0-0x004CEF50

		// Methods
		public void OnValidate(); // 0x004CE770-0x004CE860
		public void CreateEvent(Vector3 position, Vector3 velocity); // 0x004CE860-0x004CED20
	}

	[ExecuteAlways] // 0x00253190-0x002531A0
	public class CinemachineImpulseListener : CinemachineExtension // TypeDefIndex: 2691
	{
		// Fields
		public int m_ChannelMask; // 0x28
		public float m_Gain; // 0x2C
		public bool m_Use2DDistance; // 0x30

		// Constructors
		public CinemachineImpulseListener(); // 0x004CF960-0x004CF9B0

		// Methods
		protected override void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime); // 0x004CEF50-0x004CF420
	}

	public class CinemachineImpulseManager // TypeDefIndex: 2692
	{
		// Fields
		private static CinemachineImpulseManager sInstance; // 0x00
		private List<ImpulseEvent> m_ExpiredEvents; // 0x10
		private List<ImpulseEvent> m_ActiveEvents; // 0x18
		private bool <IgnoreTimeScale>k__BackingField; // 0x20

		// Properties
		public static CinemachineImpulseManager Instance { get; } // 0x004CEE30-0x004CEE90
		public bool IgnoreTimeScale { get; } // 0x004CF9C0-0x004CF9D0
		private float CurrentTime { get; } // 0x004CF9D0-0x004CFA50

		// Nested types
		[Serializable]
		public struct EnvelopeDefinition // TypeDefIndex: 2693
		{
			// Fields
			public AnimationCurve m_AttackShape; // 0x00
			public AnimationCurve m_DecayShape; // 0x08
			public float m_AttackTime; // 0x10
			public float m_SustainTime; // 0x14
			public float m_DecayTime; // 0x18
			public bool m_ScaleWithImpact; // 0x1C
			public bool m_HoldForever; // 0x1D

			// Properties
			public float Duration { get; } // 0x00280800-0x00280820

			// Methods
			public static EnvelopeDefinition Default(); // 0x00AB6190-0x00AB65D0
			public float GetValueAt(float offset); // 0x00280820-0x00280830
			public void Clear(); // 0x00280830-0x00280840
			public void Validate(); // 0x00280840-0x00280910
		}

		public class ImpulseEvent // TypeDefIndex: 2694
		{
			// Fields
			public float m_StartTime; // 0x10
			public EnvelopeDefinition m_Envelope; // 0x18
			public ISignalSource6D m_SignalSource; // 0x38
			public Vector3 m_Position; // 0x40
			public float m_Radius; // 0x4C
			public DirectionMode m_DirectionMode; // 0x50
			public int m_Channel; // 0x54
			public DissipationMode m_DissipationMode; // 0x58
			public float m_DissipationDistance; // 0x5C

			// Properties
			public bool Expired { get; } // 0x00AB65D0-0x00AB6690

			// Nested types
			public enum DirectionMode // TypeDefIndex: 2695
			{
				Fixed = 0,
				RotateTowardSource = 1
			}

			public enum DissipationMode // TypeDefIndex: 2696
			{
				LinearDecay = 0,
				SoftDecay = 1,
				ExponentialDecay = 2
			}

			// Constructors
			internal ImpulseEvent(); // 0x00AB7450-0x00AB7460

			// Methods
			public float DistanceDecay(float distance); // 0x00AB6690-0x00AB6960
			public bool GetDecayedSignal(Vector3 listenerPosition, bool use2D, out Vector3 pos, out Quaternion rot); // 0x00AB6960-0x00AB7380
			public void Clear(); // 0x00AB7380-0x00AB7450
		}

		// Constructors
		private CinemachineImpulseManager(); // 0x004CF9B0-0x004CF9C0

		// Methods
		public bool GetImpulseAt(Vector3 listenerLocation, bool distance2D, int channelMask, out Vector3 pos, out Quaternion rot); // 0x004CF420-0x004CF960
		public ImpulseEvent NewImpulseEvent(); // 0x004CEE90-0x004CEEF0
		public void AddImpulseEvent(ImpulseEvent e); // 0x004CED20-0x004CEE30
	}

	public class CinemachineImpulseSource : MonoBehaviour // TypeDefIndex: 2697
	{
		// Fields
		public CinemachineImpulseDefinition m_ImpulseDefinition; // 0x18

		// Constructors
		public CinemachineImpulseSource(); // 0x004CFDB0-0x004CFE80

		// Methods
		private void OnValidate(); // 0x004CFA50-0x004CFB40
		public void GenerateImpulseAt(Vector3 position, Vector3 velocity); // 0x004CFB40-0x004CFB50
		public void GenerateImpulse(Vector3 velocity); // 0x004CFB50-0x004CFC40
		public void GenerateImpulse(); // 0x004CFC40-0x004CFDB0
	}
}

namespace Cinemachine.PostFX
{
	[ExecuteAlways] // 0x002531A0-0x002531B0
	public class CinemachinePostProcessing : CinemachineExtension // TypeDefIndex: 2698
	{
		// Fields
		public bool m_FocusTracksTarget; // 0x28
		public float m_FocusOffset; // 0x2C
		public PostProcessProfile m_Profile; // 0x30
		private static string sVolumeOwnerName; // 0x00
		private static List<PostProcessVolume> sVolumes; // 0x08
		private static Dictionary<CinemachineBrain, PostProcessLayer> mBrainToLayer; // 0x10

		// Properties
		public bool IsValid { get; } // 0x004DAAD0-0x004DABE0

		// Nested types
		private class VcamExtraState // TypeDefIndex: 2699
		{
			// Fields
			public PostProcessProfile mProfileCopy; // 0x10

			// Constructors
			public VcamExtraState(); // 0x00AB7FC0-0x00AB7FE0

			// Methods
			public void CreateProfileCopy(PostProcessProfile source); // 0x00AB7B80-0x00AB7EC0
			public void DestroyProfileCopy(); // 0x00AB7EC0-0x00AB7FC0
		}

		// Constructors
		public CinemachinePostProcessing(); // 0x004DC7B0-0x004DC7F0
		static CinemachinePostProcessing(); // 0x004DC7F0-0x004DC8A0

		// Methods
		public void InvalidateCachedProfile(); // 0x004DABE0-0x004DAC70
		protected override void OnDestroy(); // 0x004DAC70-0x004DACA0
		protected override void PostPipelineStageCallback(CinemachineVirtualCameraBase vcam, CinemachineCore.Stage stage, ref CameraState state, float deltaTime); // 0x004DACA0-0x004DB200
		private static void OnCameraCut(CinemachineBrain brain); // 0x004DB200-0x004DB310
		private static void ApplyPostFX(CinemachineBrain brain); // 0x004DB580-0x004DBAB0
		private static List<PostProcessVolume> GetDynamicBrainVolumes(CinemachineBrain brain, PostProcessLayer ppLayer, int minVolumes); // 0x004DBAB0-0x004DC380
		private static PostProcessLayer GetPPLayer(CinemachineBrain brain); // 0x004DB310-0x004DB580
		private static void OnSceneUnloaded(Scene scene); // 0x004DC380-0x004DC5E0
		[RuntimeInitializeOnLoadMethod] // 0x002536C0-0x002536D0
		private static void InitializeModule(); // 0x004DC5E0-0x004DC7B0
	}

	public class CinemachineVolumeSettings : MonoBehaviour // TypeDefIndex: 2700
	{
		// Constructors
		public CinemachineVolumeSettings(); // 0x00AA9F20-0x00AA9F60
	}
}

namespace Cinemachine.Utility
{
	public class CinemachineDebug // TypeDefIndex: 2701
	{
		// Fields
		private static HashSet<UnityEngine.Object> mClients; // 0x00
		public static OnGUIDelegate OnGUIHandlers; // 0x08
		private static List<StringBuilder> mAvailableStringBuilders; // 0x10

		// Nested types
		public delegate void OnGUIDelegate(); // TypeDefIndex: 2702; 0x00AB4F50-0x00AB5190

		// Methods
		public static void ReleaseScreenPos(UnityEngine.Object client); // 0x006866D0-0x00686750
		public static Rect GetScreenPos(UnityEngine.Object client, string text, GUIStyle style); // 0x00686380-0x006866D0
		public static StringBuilder SBFromPool(); // 0x006836A0-0x00683770
		public static void ReturnToPool(StringBuilder sb); // 0x00683770-0x00683800
	}

	internal abstract class GaussianWindow1d<T> // TypeDefIndex: 2703
	{
		// Fields
		protected T[] mData;
		protected float[] mKernel;
		protected int mCurrentPos;
		private float <Sigma>k__BackingField;

		// Properties
		private float Sigma { set; }
		public int KernelSize { get; }

		// Constructors
		public GaussianWindow1d(float sigma, int maxKernelRadius = 10 /* Metadata: 0x0015A9A1 */);

		// Methods
		private void GenerateKernel(float sigma, int maxKernelRadius);
		protected abstract T Compute(int windowPos);
		public void Reset();
		public bool IsEmpty();
		public void AddValue(T v);
		public T Value();
	}

	internal class GaussianWindow1D_Vector3 : GaussianWindow1d<Vector3> // TypeDefIndex: 2704
	{
		// Constructors
		public GaussianWindow1D_Vector3(float sigma, int maxKernelRadius = 10 /* Metadata: 0x0015A9A5 */); // 0x00AAA340-0x00AAA400

		// Methods
		protected override Vector3 Compute(int windowPos); // 0x00AAA400-0x00AAA5C0
	}

	public class PositionPredictor // TypeDefIndex: 2705
	{
		// Fields
		private Vector3 m_Position; // 0x10
		private GaussianWindow1D_Vector3 m_Velocity; // 0x20
		private GaussianWindow1D_Vector3 m_Accel; // 0x28
		private float mLastVelAddedTime; // 0x30
		private const float kSmoothingDefault = 10f; // Metadata: 0x0015A9A9
		private float mSmoothing; // 0x34

		// Properties
		public float Smoothing { set; } // 0x00AAC550-0x00AAC7B0
		public bool IsEmpty { get; } // 0x00AAC7B0-0x00AAC7F0

		// Constructors
		public PositionPredictor(); // 0x00AACEB0-0x00AAD060

		// Methods
		public void ApplyTransformDelta(Vector3 positionDelta); // 0x00AAC7F0-0x00AAC8A0
		public void Reset(); // 0x00AAC8A0-0x00AAC8F0
		public void AddPosition(Vector3 pos, float deltaTime, float lookaheadTime); // 0x00AAC8F0-0x00AACCB0
		public Vector3 PredictPositionDelta(float lookaheadTime); // 0x00AACCB0-0x00AACEB0
	}

	public static class Damper // TypeDefIndex: 2706
	{
		// Methods
		public static float Damp(float initial, float dampTime, float deltaTime); // 0x00AA9F60-0x00AAA0A0
		public static Vector3 Damp(Vector3 initial, Vector3 dampTime, float deltaTime); // 0x00AAA0A0-0x00AAA1F0
		public static Vector3 Damp(Vector3 initial, float dampTime, float deltaTime); // 0x00AAA1F0-0x00AAA340
	}

	public class HeadingTracker // TypeDefIndex: 2707
	{
		// Fields
		private Item[] mHistory; // 0x10
		private int mTop; // 0x18
		private int mBottom; // 0x1C
		private int mCount; // 0x20
		private Vector3 mHeadingSum; // 0x24
		private float mWeightSum; // 0x30
		private float mWeightTime; // 0x34
		private Vector3 mLastGoodHeading; // 0x38
		private static float mDecayExponent; // 0x00

		// Properties
		public int FilterSize { get; } // 0x00AAA820-0x00AAA840

		// Nested types
		private struct Item // TypeDefIndex: 2708
		{
			// Fields
			public Vector3 velocity; // 0x00
			public float weight; // 0x0C
			public float time; // 0x10
		}

		// Constructors
		public HeadingTracker(int filterSize); // 0x00AAA5C0-0x00AAA770

		// Methods
		private void ClearHistory(); // 0x00AAA770-0x00AAA820
		private static float Decay(float time); // 0x00AAA840-0x00AAA8C0
		public void Add(Vector3 velocity); // 0x00AAA8C0-0x00AAABC0
		private void PopBottom(); // 0x00AAABC0-0x00AAAE80
		public void DecayHistory(); // 0x00AAAE80-0x00AAB0A0
		public Vector3 GetReliableHeading(); // 0x00AAB0A0-0x00AAB230
	}

	public static class SplineHelpers // TypeDefIndex: 2709
	{
		// Methods
		public static Vector3 Bezier3(float t, Vector3 p0, Vector3 p1, Vector3 p2, Vector3 p3); // 0x00AAD160-0x00AAD380
		public static Vector3 BezierTangent3(float t, Vector3 p0, Vector3 p1, Vector3 p2, Vector3 p3); // 0x00AAD380-0x00AAD670
		public static float Bezier1(float t, float p0, float p1, float p2, float p3); // 0x00AAD670-0x00AAD790
		public static void ComputeSmoothControlPoints(ref Vector4[] knot, ref Vector4[] ctrl1, ref Vector4[] ctrl2); // 0x00AAD790-0x00AAE930
		public static void ComputeSmoothControlPointsLooped(ref Vector4[] knot, ref Vector4[] ctrl1, ref Vector4[] ctrl2); // 0x00AAE930-0x00AAEDF0
	}

	public static class UnityVectorExtensions // TypeDefIndex: 2710
	{
		// Methods
		public static float ClosestPointOnSegment(Vector3 p, Vector3 s0, Vector3 s1); // 0x00AB10C0-0x00AB12A0
		public static float ClosestPointOnSegment(Vector2 p, Vector2 s0, Vector2 s1); // 0x00AB12A0-0x00AB1400
		public static Vector3 ProjectOntoPlane(Vector3 vector, Vector3 planeNormal); // 0x00AAF930-0x00AAFA10
		public static Vector3 Abs(Vector3 v); // 0x00AB1400-0x00AB1490
		public static bool AlmostZero(Vector3 v); // 0x00AAB230-0x00AAB300
		public static float Angle(Vector3 v1, Vector3 v2); // 0x00AB0A40-0x00AB0CD0
		public static float SignedAngle(Vector3 v1, Vector3 v2, Vector3 up); // 0x00AB0CD0-0x00AB0E40
	}

	public static class UnityQuaternionExtensions // TypeDefIndex: 2711
	{
		// Methods
		public static Quaternion SlerpWithReferenceUp(Quaternion qA, Quaternion qB, float t, Vector3 up); // 0x00AAEF10-0x00AAF930
		public static Quaternion Normalized(Quaternion q); // 0x00AAFA10-0x00AAFA80
		public static Vector2 GetCameraRotationToTarget(Quaternion orient, Vector3 lookAtDir, Vector3 worldUp); // 0x00AAFA80-0x00AB0A40
		public static Quaternion ApplyCameraRotation(Quaternion orient, Vector2 rot, Vector3 worldUp); // 0x00AB0E40-0x00AB10C0
	}
}

internal sealed class <PrivateImplementationDetails> // TypeDefIndex: 2712
{
	// Fields
	internal static readonly __StaticArrayInitTypeSize=12 78517443912BB49729313EC23065D9970ABC80E3; // 0x00

	// Nested types
	private struct __StaticArrayInitTypeSize=12 // TypeDefIndex: 2713
	{
	}
}

public static class MeshExtension // TypeDefIndex: 2715
{
	// Methods
	public static void ApplyVertices(Mesh mesh, Vector3[] vertices, int count); // 0x00B1D900-0x00B1DA70
	public static void ApplyNormals(Mesh mesh, Vector3[] normals, int count); // 0x00B1DA70-0x00B1DBE0
	public static void ApplyTangents(Mesh mesh, Vector4[] tangents, int count); // 0x00B1DBE0-0x00B1DD50
	public static void ApplyUvs(Mesh mesh, Vector2[] uvs, int channel, int count); // 0x00B1DD50-0x00B1E0B0
	public static void ApplyColors32(Mesh mesh, Color32[] colors32, int count); // 0x00B1E0B0-0x00B1E200
	public static void ApplyTriangles(Mesh mesh, int[] triangles, int count); // 0x00B1E200-0x00B1E300
}

namespace TMPro
{
	public class FastAction // TypeDefIndex: 2717
	{
		// Fields
		private LinkedList<Action> delegates; // 0x10
		private Dictionary<Action, LinkedListNode<Action>> lookup; // 0x18

		// Constructors
		public FastAction(); // 0x0037CE60-0x0037D1A0
	}

	public class FastAction<A> // TypeDefIndex: 2718
	{
		// Fields
		private LinkedList<Action<A>> delegates;
		private Dictionary<Action<A>, LinkedListNode<Action<A>>> lookup;

		// Constructors
		public FastAction();

		// Methods
		public void Add(Action<A> rhs);
		public void Remove(Action<A> rhs);
		public void Call(A a);
	}

	public class FastAction<A, B> // TypeDefIndex: 2719
	{
		// Fields
		private LinkedList<Action<A, B>> delegates;
		private Dictionary<Action<A, B>, LinkedListNode<Action<A, B>>> lookup;

		// Constructors
		public FastAction();
	}

	public class FastAction<A, B, C> // TypeDefIndex: 2720
	{
		// Fields
		private LinkedList<Action<A, B, C>> delegates;
		private Dictionary<Action<A, B, C>, LinkedListNode<Action<A, B, C>>> lookup;

		// Constructors
		public FastAction();
	}

	public interface ITextPreprocessor // TypeDefIndex: 2721
	{
		// Methods
		string PreprocessText(string text);
	}

	public class MaterialReferenceManager // TypeDefIndex: 2722
	{
		// Fields
		private static MaterialReferenceManager s_Instance; // 0x00
		private Dictionary<int, Material> m_FontMaterialReferenceLookup; // 0x10
		private Dictionary<int, TMP_FontAsset> m_FontAssetReferenceLookup; // 0x18
		private Dictionary<int, TMP_SpriteAsset> m_SpriteAssetReferenceLookup; // 0x20
		private Dictionary<int, TMP_ColorGradient> m_ColorGradientReferenceLookup; // 0x28

		// Properties
		public static MaterialReferenceManager instance { get; } // 0x0037D8C0-0x0037D930

		// Constructors
		public MaterialReferenceManager(); // 0x0037D930-0x0037DA40

		// Methods
		public static void AddFontAsset(TMP_FontAsset fontAsset); // 0x0037DA40-0x0037DAD0
		private void AddFontAssetInternal(TMP_FontAsset fontAsset); // 0x0037DAD0-0x0037DBA0
		public static void AddSpriteAsset(int hashCode, TMP_SpriteAsset spriteAsset); // 0x0037DBA0-0x0037DC30
		private void AddSpriteAssetInternal(int hashCode, TMP_SpriteAsset spriteAsset); // 0x0037DC30-0x0037DD00
		public static void AddFontMaterial(int hashCode, Material material); // 0x0037DD00-0x0037DDD0
		private void AddFontMaterialInternal(int hashCode, Material material); // 0x0037DDD0-0x0037DE30
		public static void AddColorGradientPreset(int hashCode, TMP_ColorGradient spriteAsset); // 0x0037DE30-0x0037DF20
		private void AddColorGradientPreset_Internal(int hashCode, TMP_ColorGradient spriteAsset); // 0x0037DF20-0x0037DFB0
		public static bool TryGetFontAsset(int hashCode, out TMP_FontAsset fontAsset); // 0x0037DFB0-0x0037E0C0
		private bool TryGetFontAssetInternal(int hashCode, out TMP_FontAsset fontAsset); // 0x0037E0C0-0x0037E160
		public static bool TryGetSpriteAsset(int hashCode, out TMP_SpriteAsset spriteAsset); // 0x0037E160-0x0037E270
		private bool TryGetSpriteAssetInternal(int hashCode, out TMP_SpriteAsset spriteAsset); // 0x0037E270-0x0037E310
		public static bool TryGetColorGradientPreset(int hashCode, out TMP_ColorGradient gradientPreset); // 0x0037E310-0x0037E420
		private bool TryGetColorGradientPresetInternal(int hashCode, out TMP_ColorGradient gradientPreset); // 0x0037E420-0x0037E4C0
		public static bool TryGetMaterial(int hashCode, out Material material); // 0x0037E4C0-0x0037E5D0
		private bool TryGetMaterialInternal(int hashCode, out Material material); // 0x0037E5D0-0x0037E670
	}

	public struct MaterialReference // TypeDefIndex: 2723
	{
		// Fields
		public int index; // 0x00
		public TMP_FontAsset fontAsset; // 0x08
		public TMP_SpriteAsset spriteAsset; // 0x10
		public Material material; // 0x18
		public bool isDefaultMaterial; // 0x20
		public bool isFallbackMaterial; // 0x21
		public Material fallbackMaterial; // 0x28
		public float padding; // 0x30
		public int referenceCount; // 0x34

		// Constructors
		public MaterialReference(int index, TMP_FontAsset fontAsset, TMP_SpriteAsset spriteAsset, Material material, float padding); // 0x002567D0-0x002568A0

		// Methods
		public static int AddMaterialReference(Material material, TMP_FontAsset fontAsset, MaterialReference[] materialReferences, Dictionary<int, int> materialReferenceIndexLookup); // 0x0037D660-0x0037D7A0
		public static int AddMaterialReference(Material material, TMP_SpriteAsset spriteAsset, MaterialReference[] materialReferences, Dictionary<int, int> materialReferenceIndexLookup); // 0x0037D7A0-0x0037D8C0
	}

	[Serializable]
	public class TMP_Asset : ScriptableObject // TypeDefIndex: 2724
	{
		// Fields
		private int m_InstanceID; // 0x18
		public int hashCode; // 0x1C
		public Material material; // 0x20
		public int materialHashCode; // 0x28

		// Properties
		public int instanceID { get; } // 0x00381970-0x00381990

		// Constructors
		public TMP_Asset(); // 0x00381990-0x003819A0
	}

	[Serializable]
	public class TMP_Character : TMP_TextElement // TypeDefIndex: 2725
	{
		// Constructors
		public TMP_Character(); // 0x003819A0-0x003819B0
		public TMP_Character(uint unicode, Glyph glyph); // 0x003819B0-0x003819E0
		internal TMP_Character(uint unicode, uint glyphIndex); // 0x003819E0-0x00381A00
	}

	public struct TMP_Vertex // TypeDefIndex: 2726
	{
		// Fields
		public Vector3 position; // 0x00
		public Vector2 uv; // 0x0C
		public Vector2 uv2; // 0x14
		public Vector2 uv4; // 0x1C
		public Color32 color; // 0x24
		private static readonly TMP_Vertex k_Zero; // 0x00
	}

	public struct TMP_Offset // TypeDefIndex: 2727
	{
		// Fields
		private float m_Left; // 0x00
		private float m_Right; // 0x04
		private float m_Top; // 0x08
		private float m_Bottom; // 0x0C
		private static readonly TMP_Offset k_ZeroOffset; // 0x00

		// Properties
		public float left { get; } // 0x002291D0-0x002291E0
		public float right { get; } // 0x002291E0-0x002291F0
		public float top { get; } // 0x002291F0-0x00229200
		public float bottom { get; } // 0x00229200-0x00229210
		public static TMP_Offset zero { get; } // 0x0032B0F0-0x0032B170

		// Constructors
		public TMP_Offset(float left, float right, float top, float bottom); // 0x00229210-0x00229230
		static TMP_Offset(); // 0x0032B280-0x0032B2C0

		// Methods
		public static bool operator ==(TMP_Offset lhs, TMP_Offset rhs); // 0x0032B170-0x0032B1B0
		public static TMP_Offset operator *(TMP_Offset a, float b); // 0x0032B1B0-0x0032B280
		public override int GetHashCode(); // 0x00229230-0x00229290
		public override bool Equals(object obj); // 0x00229290-0x00229390
	}

	public struct HighlightState // TypeDefIndex: 2728
	{
		// Fields
		public Color32 color; // 0x00
		public TMP_Offset padding; // 0x04

		// Constructors
		public HighlightState(Color32 color, TMP_Offset padding); // 0x002566A0-0x002566B0

		// Methods
		public static bool operator ==(HighlightState lhs, HighlightState rhs); // 0x0037D1A0-0x0037D2B0
		public static bool operator !=(HighlightState lhs, HighlightState rhs); // 0x0037D2B0-0x0037D4B0
		public override int GetHashCode(); // 0x002566B0-0x00256710
		public override bool Equals(object obj); // 0x00256710-0x002567D0
	}

	public struct TMP_CharacterInfo // TypeDefIndex: 2729
	{
		// Fields
		public char character; // 0x00
		public int index; // 0x04
		public int stringLength; // 0x08
		public TMP_TextElementType elementType; // 0x0C
		public TMP_TextElement textElement; // 0x10
		public TMP_FontAsset fontAsset; // 0x18
		public TMP_SpriteAsset spriteAsset; // 0x20
		public int spriteIndex; // 0x28
		public Material material; // 0x30
		public int materialReferenceIndex; // 0x38
		public bool isUsingAlternateTypeface; // 0x3C
		public float pointSize; // 0x40
		public int lineNumber; // 0x44
		public int pageNumber; // 0x48
		public int vertexIndex; // 0x4C
		public TMP_Vertex vertex_BL; // 0x50
		public TMP_Vertex vertex_TL; // 0x78
		public TMP_Vertex vertex_TR; // 0xA0
		public TMP_Vertex vertex_BR; // 0xC8
		public Vector3 topLeft; // 0xF0
		public Vector3 bottomLeft; // 0xFC
		public Vector3 topRight; // 0x108
		public Vector3 bottomRight; // 0x114
		public float origin; // 0x120
		public float ascender; // 0x124
		public float baseLine; // 0x128
		public float descender; // 0x12C
		public float xAdvance; // 0x130
		public float aspectRatio; // 0x134
		public float scale; // 0x138
		public Color32 color; // 0x13C
		public Color32 underlineColor; // 0x140
		public int underlineVertexIndex; // 0x144
		public Color32 strikethroughColor; // 0x148
		public int strikethroughVertexIndex; // 0x14C
		public Color32 highlightColor; // 0x150
		public HighlightState highlightState; // 0x154
		public FontStyles style; // 0x168
		public bool isVisible; // 0x16C
	}

	public enum ColorMode // TypeDefIndex: 2730
	{
		Single = 0,
		HorizontalGradient = 1,
		VerticalGradient = 2,
		FourCornersGradient = 3
	}

	[Serializable]
	public class TMP_ColorGradient : ScriptableObject // TypeDefIndex: 2731
	{
		// Fields
		public ColorMode colorMode; // 0x18
		public Color topLeft; // 0x1C
		public Color topRight; // 0x2C
		public Color bottomLeft; // 0x3C
		public Color bottomRight; // 0x4C
		private const ColorMode k_DefaultColorMode = ColorMode.FourCornersGradient; // Metadata: 0x0015A9C9
		private static readonly Color k_DefaultColor; // 0x00

		// Constructors
		public TMP_ColorGradient(); // 0x00381A00-0x00381AA0
		public TMP_ColorGradient(Color color); // 0x00381AA0-0x00381AF0
		public TMP_ColorGradient(Color color0, Color color1, Color color2, Color color3); // 0x00381AF0-0x00381B80
		static TMP_ColorGradient(); // 0x00381B80-0x00381BC0
	}

	public static class TMP_Compatibility // TypeDefIndex: 2732
	{
		// Methods
		public static TextAlignmentOptions ConvertTextAlignmentEnumValues(TextAlignmentOptions oldValue); // 0x00381BC0-0x00381BE0
	}

	internal interface ITweenValue // TypeDefIndex: 2733
	{
		// Properties
		bool ignoreTimeScale { get; }
		float duration { get; }

		// Methods
		void TweenValue(float floatPercentage);
		bool ValidTarget();
	}

	internal struct FloatTween : TMPro.ITweenValue // TypeDefIndex: 2734
	{
		// Fields
		private FloatTweenCallback m_Target; // 0x00
		private float m_StartValue; // 0x08
		private float m_TargetValue; // 0x0C
		private float m_Duration; // 0x10
		private bool m_IgnoreTimeScale; // 0x14

		// Properties
		public float startValue { set; } // 0x00256360-0x00256370
		public float targetValue { set; } // 0x00256370-0x00256380
		public float duration { get; set; } // 0x00256380-0x00256390 0x00256390-0x002563A0
		public bool ignoreTimeScale { get; set; } // 0x002563A0-0x002563B0 0x002563B0-0x002563C0

		// Nested types
		public class FloatTweenCallback : UnityEvent<float> // TypeDefIndex: 2735
		{
			// Constructors
			public FloatTweenCallback(); // 0x0067C840-0x0067C880
		}

		// Methods
		public void TweenValue(float floatPercentage); // 0x002563C0-0x002563D0
		public void AddOnChangedCallback(UnityAction<float> callback); // 0x002563D0-0x002564B0
		public bool ValidTarget(); // 0x002564B0-0x00256660
	}

	internal class TweenRunner<T> // TypeDefIndex: 2736
		where T : struct, TMPro.ITweenValue
	{
		// Fields
		protected MonoBehaviour m_CoroutineContainer;
		protected IEnumerator m_Tween;

		// Nested types
		private sealed class <Start>d__2 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2737
		{
			// Fields
			private int <>1__state;
			private object <>2__current;
			public T tweenInfo;
			private float <elapsedTime>5__2;

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x002548D0-0x002548E0 */ get; }
			object IEnumerator.Current { [DebuggerHidden] /* 0x002548E0-0x002548F0 */ get; }

			// Constructors
			[DebuggerHidden] // 0x002548B0-0x002548C0
			public <Start>d__2(int <>1__state);

			// Methods
			[DebuggerHidden] // 0x002548C0-0x002548D0
			void IDisposable.Dispose();
			private bool MoveNext();
		}

		// Constructors
		public TweenRunner();

		// Methods
		private static IEnumerator Start(T tweenInfo);
		public void Init(MonoBehaviour coroutineContainer);
		public void StartTween(T info);
		public void StopTween();
	}

	[RequireComponent] // 0x00253710-0x00253750
	public class TMP_Dropdown : Selectable, IPointerClickHandler, IEventSystemHandler, ISubmitHandler, ICancelHandler // TypeDefIndex: 2738
	{
		// Fields
		[SerializeField] // 0x00253950-0x00253960
		private RectTransform m_Template; // 0xF0
		[SerializeField] // 0x00253960-0x00253970
		private TMP_Text m_CaptionText; // 0xF8
		[SerializeField] // 0x00253970-0x00253980
		private Image m_CaptionImage; // 0x100
		[SerializeField] // 0x00253980-0x00253990
		private Graphic m_Placeholder; // 0x108
		[SerializeField] // 0x00253990-0x002539A0
		private TMP_Text m_ItemText; // 0x110
		[SerializeField] // 0x002539A0-0x002539B0
		private Image m_ItemImage; // 0x118
		[SerializeField] // 0x002539B0-0x002539C0
		private int m_Value; // 0x120
		[SerializeField] // 0x002539C0-0x002539D0
		private OptionDataList m_Options; // 0x128
		[SerializeField] // 0x002539D0-0x002539E0
		private DropdownEvent m_OnValueChanged; // 0x130
		[SerializeField] // 0x002539E0-0x002539F0
		private float m_AlphaFadeSpeed; // 0x138
		private GameObject m_Dropdown; // 0x140
		private GameObject m_Blocker; // 0x148
		private List<DropdownItem> m_Items; // 0x150
		private TMPro.TweenRunner<TMPro.FloatTween> m_AlphaTweenRunner; // 0x158
		private bool validTemplate; // 0x160
		private Coroutine m_Coroutine; // 0x168
		private static OptionData s_NoOptionData; // 0x00

		// Properties
		public RectTransform template { get; set; } // 0x00381BE0-0x00381BF0 0x00381BF0-0x00381C00
		public TMP_Text captionText { get; set; } // 0x00381F70-0x00381F80 0x00381F80-0x00381F90
		public Image captionImage { get; set; } // 0x00381F90-0x00381FA0 0x00381FA0-0x00381FB0
		public Graphic placeholder { get; set; } // 0x00381FB0-0x00381FC0 0x00381FC0-0x00381FD0
		public TMP_Text itemText { get; set; } // 0x00381FD0-0x00381FE0 0x00381FE0-0x00381FF0
		public Image itemImage { get; set; } // 0x00381FF0-0x00382000 0x00382000-0x00382010
		public List<OptionData> options { get; set; } // 0x00382010-0x00382030 0x00382030-0x00382050
		public DropdownEvent onValueChanged { get; set; } // 0x00382050-0x00382060 0x00382060-0x00382070
		public float alphaFadeSpeed { get; set; } // 0x00382070-0x00382080 0x00382080-0x00382090
		public int value { get; set; } // 0x00382090-0x003820A0 0x003820A0-0x003820B0
		public bool IsExpanded { get; } // 0x00382280-0x00382370

		// Nested types
		protected internal class DropdownItem : MonoBehaviour, IPointerEnterHandler, IEventSystemHandler, ICancelHandler // TypeDefIndex: 2739
		{
			// Fields
			[SerializeField] // 0x002539F0-0x00253A00
			private TMP_Text m_Text; // 0x18
			[SerializeField] // 0x00253A00-0x00253A10
			private Image m_Image; // 0x20
			[SerializeField] // 0x00253A10-0x00253A20
			private RectTransform m_RectTransform; // 0x28
			[SerializeField] // 0x00253A20-0x00253A30
			private Toggle m_Toggle; // 0x30

			// Properties
			public TMP_Text text { get; set; } // 0x0067C9C0-0x0067C9D0 0x0067C9D0-0x0067C9E0
			public Image image { get; set; } // 0x0067C9E0-0x0067C9F0 0x0067C9F0-0x0067CA00
			public RectTransform rectTransform { get; set; } // 0x0067CA00-0x0067CA10 0x0067CA10-0x0067CA20
			public Toggle toggle { get; set; } // 0x0067CA20-0x0067CA30 0x0067CA30-0x0067CA40

			// Constructors
			public DropdownItem(); // 0x0067CBA0-0x0067D9A0

			// Methods
			public virtual void OnPointerEnter(PointerEventData eventData); // 0x0067CA40-0x0067CB30
			public virtual void OnCancel(BaseEventData eventData); // 0x0067CB30-0x0067CBA0
		}

		[Serializable]
		public class OptionData // TypeDefIndex: 2740
		{
			// Fields
			[SerializeField] // 0x00253A30-0x00253A40
			private string m_Text; // 0x10
			[SerializeField] // 0x00253A40-0x00253A50
			private Sprite m_Image; // 0x18

			// Properties
			public string text { get; set; } // 0x00AC65B0-0x00AC65C0 0x00AC65C0-0x00AC65D0
			public Sprite image { get; set; } // 0x00AC65D0-0x00AC65E0 0x00AC65E0-0x00AC65F0

			// Constructors
			public OptionData(); // 0x00AC65F0-0x00AC6600
			public OptionData(string text); // 0x00AC6600-0x00AC6610
			public OptionData(Sprite image); // 0x00AC6610-0x00AC6620
		}

		[Serializable]
		public class OptionDataList // TypeDefIndex: 2741
		{
			// Fields
			[SerializeField] // 0x00253A50-0x00253A60
			private List<OptionData> m_Options; // 0x10

			// Properties
			public List<OptionData> options { get; set; } // 0x00AC6620-0x00AC6630 0x00AC6630-0x00AC6640

			// Constructors
			public OptionDataList(); // 0x00AC6640-0x00AC6690
		}

		[Serializable]
		public class DropdownEvent : UnityEvent<int> // TypeDefIndex: 2742
		{
			// Constructors
			public DropdownEvent(); // 0x0067C980-0x0067C9C0
		}

		private sealed class <>c__DisplayClass69_0 // TypeDefIndex: 2743
		{
			// Fields
			public DropdownItem item; // 0x10
			public TMP_Dropdown <>4__this; // 0x18

			// Constructors
			public <>c__DisplayClass69_0(); // 0x0067C880-0x0067C890

			// Methods
			internal void <Show>b__0(bool x); // 0x0067C890-0x0067C8C0
		}

		private sealed class <DelayedDestroyDropdownList>d__81 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2744
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public float delay; // 0x20
			public TMP_Dropdown <>4__this; // 0x28

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00254910-0x00254920 */ get; } // 0x0067C960-0x0067C970
			object IEnumerator.Current { [DebuggerHidden] /* 0x00254920-0x00254930 */ get; } // 0x0067C970-0x0067C980

			// Constructors
			[DebuggerHidden] // 0x002548F0-0x00254900
			public <DelayedDestroyDropdownList>d__81(int <>1__state); // 0x0067C8C0-0x0067C8D0

			// Methods
			[DebuggerHidden] // 0x00254900-0x00254910
			void IDisposable.Dispose(); // 0x0067C8D0-0x0067C8E0
			private bool MoveNext(); // 0x0067C8E0-0x0067C960
		}

		// Constructors
		protected TMP_Dropdown(); // 0x00382370-0x00382490
		static TMP_Dropdown(); // 0x003873D0-0x00387410

		// Methods
		public void SetValueWithoutNotify(int input); // 0x00382270-0x00382280
		private void SetValue(int value, bool sendCallback = true /* Metadata: 0x0015A9CD */); // 0x003820B0-0x00382270
		protected override void Awake(); // 0x00382490-0x003826E0
		protected override void Start(); // 0x003826E0-0x003826F0
		protected override void OnDisable(); // 0x003826F0-0x00382810
		public void RefreshShownValue(); // 0x00381C00-0x00381F70
		public void AddOptions(List<OptionData> options); // 0x00382AD0-0x00382B40
		public void AddOptions(List<string> options); // 0x00382B40-0x00382BF0
		public void AddOptions(List<Sprite> options); // 0x00382BF0-0x00382CA0
		public void ClearOptions(); // 0x00382CA0-0x00382D40
		private void SetupTemplate(); // 0x00382D40-0x00383C30
		private static T GetOrAddComponent<T>(GameObject go)
			where T : Component;
		public virtual void OnPointerClick(PointerEventData eventData); // 0x00383C30-0x00383C40
		public virtual void OnSubmit(BaseEventData eventData); // 0x003860E0-0x003860F0
		public virtual void OnCancel(BaseEventData eventData); // 0x003860F0-0x00386100
		public void Show(); // 0x00383C40-0x00385A30
		protected virtual GameObject CreateBlocker(Canvas rootCanvas); // 0x00386420-0x00386E20
		protected virtual void DestroyBlocker(GameObject blocker); // 0x00386E20-0x00386E70
		protected virtual GameObject CreateDropdownList(GameObject template); // 0x00386E70-0x00386EC0
		protected virtual void DestroyDropdownList(GameObject dropdownList); // 0x00386EC0-0x00386F10
		protected virtual DropdownItem CreateItem(DropdownItem itemTemplate); // 0x00386F10-0x00386F60
		protected virtual void DestroyItem(DropdownItem item); // 0x00386F60-0x00386F70
		private DropdownItem AddItem(OptionData data, bool selected, DropdownItem itemTemplate, List<DropdownItem> items); // 0x00385A30-0x00385F00
		private void AlphaFadeList(float duration, float alpha); // 0x00386F70-0x00387020
		private void AlphaFadeList(float duration, float start, float end); // 0x00385F00-0x003860E0
		private void SetAlpha(float alpha); // 0x00387020-0x00387100
		public void Hide(); // 0x00386100-0x00386420
		private IEnumerator DelayedDestroyDropdownList(float delay); // 0x00387100-0x00387160
		private void ImmediateDestroyDropdownList(); // 0x00382810-0x00382AD0
		private void OnSelectItem(Toggle toggle); // 0x00387160-0x003873D0
	}

	public enum AtlasPopulationMode // TypeDefIndex: 2745
	{
		Static = 0,
		Dynamic = 1
	}

	[Serializable]
	public class TMP_FontAsset : TMP_Asset // TypeDefIndex: 2746
	{
		// Fields
		[SerializeField] // 0x00253A60-0x00253A70
		private string m_Version; // 0x30
		[SerializeField] // 0x00253A70-0x00253A80
		internal string m_SourceFontFileGUID; // 0x38
		[SerializeField] // 0x00253A80-0x00253A90
		private Font m_SourceFontFile; // 0x40
		[SerializeField] // 0x00253A90-0x00253AA0
		private AtlasPopulationMode m_AtlasPopulationMode; // 0x48
		[SerializeField] // 0x00253AA0-0x00253AB0
		internal FaceInfo m_FaceInfo; // 0x50
		[SerializeField] // 0x00253AB0-0x00253AC0
		internal List<Glyph> m_GlyphTable; // 0xA8
		internal Dictionary<uint, Glyph> m_GlyphLookupDictionary; // 0xB0
		[SerializeField] // 0x00253AC0-0x00253AD0
		internal List<TMP_Character> m_CharacterTable; // 0xB8
		internal Dictionary<uint, TMP_Character> m_CharacterLookupDictionary; // 0xC0
		internal Texture2D m_AtlasTexture; // 0xC8
		[SerializeField] // 0x00253AD0-0x00253AE0
		internal Texture2D[] m_AtlasTextures; // 0xD0
		[SerializeField] // 0x00253AE0-0x00253AF0
		internal int m_AtlasTextureIndex; // 0xD8
		[SerializeField] // 0x00253AF0-0x00253B00
		private bool m_IsMultiAtlasTexturesEnabled; // 0xDC
		[SerializeField] // 0x00253B00-0x00253B10
		private List<GlyphRect> m_UsedGlyphRects; // 0xE0
		[SerializeField] // 0x00253B10-0x00253B20
		private List<GlyphRect> m_FreeGlyphRects; // 0xE8
		[SerializeField] // 0x00253B20-0x00253B30
		private FaceInfo_Legacy m_fontInfo; // 0xF0
		[SerializeField] // 0x00253B30-0x00253B40
		public Texture2D atlas; // 0xF8
		[SerializeField] // 0x00253B40-0x00253B50
		internal int m_AtlasWidth; // 0x100
		[SerializeField] // 0x00253B50-0x00253B60
		internal int m_AtlasHeight; // 0x104
		[SerializeField] // 0x00253B60-0x00253B70
		internal int m_AtlasPadding; // 0x108
		[SerializeField] // 0x00253B70-0x00253B80
		internal GlyphRenderMode m_AtlasRenderMode; // 0x10C
		[SerializeField] // 0x00253B80-0x00253B90
		internal List<TMP_Glyph> m_glyphInfoList; // 0x110
		[FormerlySerializedAs] // 0x00253B90-0x00253BB0
		[SerializeField] // 0x00253B90-0x00253BB0
		internal KerningTable m_KerningTable; // 0x118
		[SerializeField] // 0x00253BB0-0x00253BC0
		internal TMP_FontFeatureTable m_FontFeatureTable; // 0x120
		[SerializeField] // 0x00253BC0-0x00253BD0
		private List<TMP_FontAsset> fallbackFontAssets; // 0x128
		[SerializeField] // 0x00253BD0-0x00253BE0
		internal List<TMP_FontAsset> m_FallbackFontAssetTable; // 0x130
		[SerializeField] // 0x00253BE0-0x00253BF0
		internal FontAssetCreationSettings m_CreationSettings; // 0x138
		[SerializeField] // 0x00253BF0-0x00253C00
		private TMP_FontWeightPair[] m_FontWeightTable; // 0x190
		[SerializeField] // 0x00253C00-0x00253C10
		private TMP_FontWeightPair[] fontWeights; // 0x198
		public float normalStyle; // 0x1A0
		public float normalSpacingOffset; // 0x1A4
		public float boldStyle; // 0x1A8
		public float boldSpacing; // 0x1AC
		public byte italicStyle; // 0x1B0
		public byte tabSize; // 0x1B1
		private byte m_oldTabSize; // 0x1B2
		internal bool m_IsFontAssetLookupTablesDirty; // 0x1B3
		private static HashSet<int> k_SearchedFontAssetLookup; // 0x00
		private static List<TMP_FontAsset> k_FontAssets_FontFeaturesUpdateQueue; // 0x08
		private static HashSet<int> k_FontAssets_FontFeaturesUpdateQueueLookup; // 0x10
		private static List<TMP_FontAsset> k_FontAssets_AtlasTexturesUpdateQueue; // 0x18
		private static HashSet<int> k_FontAssets_AtlasTexturesUpdateQueueLookup; // 0x20
		private List<Glyph> m_GlyphsToRender; // 0x1B8
		private List<Glyph> m_GlyphsRendered; // 0x1C0
		private List<uint> m_GlyphIndexList; // 0x1C8
		private List<uint> m_GlyphIndexListNewlyAdded; // 0x1D0
		internal List<uint> m_GlyphsToAdd; // 0x1D8
		internal HashSet<uint> m_GlyphsToAddLookup; // 0x1E0
		internal List<TMP_Character> m_CharactersToAdd; // 0x1E8
		internal HashSet<uint> m_CharactersToAddLookup; // 0x1F0
		internal List<uint> s_MissingCharacterList; // 0x1F8
		internal HashSet<uint> m_MissingUnicodesFromFontFile; // 0x200
		internal static uint[] k_GlyphIndexArray; // 0x28

		// Properties
		public string version { get; internal set; } // 0x00387410-0x00387420 0x00387420-0x00387430
		public Font sourceFontFile { get; internal set; } // 0x00387430-0x00387440 0x00387440-0x00387450
		public AtlasPopulationMode atlasPopulationMode { get; set; } // 0x00387450-0x00387460 0x00387460-0x00387470
		public FaceInfo faceInfo { get; set; } // 0x00387470-0x003874B0 0x003874B0-0x003874F0
		public List<Glyph> glyphTable { get; internal set; } // 0x003874F0-0x00387500 0x00387500-0x00387510
		public Dictionary<uint, Glyph> glyphLookupTable { get; } // 0x00387510-0x00387540
		public List<TMP_Character> characterTable { get; internal set; } // 0x00388FC0-0x00388FD0 0x00388FD0-0x00388FE0
		public Dictionary<uint, TMP_Character> characterLookupTable { get; } // 0x00388FE0-0x00389010
		public Texture2D atlasTexture { get; } // 0x00389010-0x00389140
		public Texture2D[] atlasTextures { get; set; } // 0x00389140-0x00389150 0x00389150-0x00389160
		public int atlasTextureCount { get; } // 0x00389160-0x00389170
		public bool isMultiAtlasTexturesEnabled { get; set; } // 0x00389170-0x00389180 0x00389180-0x00389190
		internal List<GlyphRect> usedGlyphRects { get; set; } // 0x00389190-0x003891A0 0x003891A0-0x003891B0
		internal List<GlyphRect> freeGlyphRects { get; set; } // 0x003891B0-0x003891C0 0x003891C0-0x003891D0
		[Obsolete] // 0x00254A80-0x00254AA0
		public FaceInfo_Legacy fontInfo { get; } // 0x003891D0-0x003891E0
		public int atlasWidth { get; internal set; } // 0x003891E0-0x003891F0 0x003891F0-0x00389200
		public int atlasHeight { get; internal set; } // 0x00389200-0x00389210 0x00389210-0x00389220
		public int atlasPadding { get; internal set; } // 0x00389220-0x00389230 0x00389230-0x00389240
		public GlyphRenderMode atlasRenderMode { get; internal set; } // 0x00389240-0x00389250 0x00389250-0x00389260
		public TMP_FontFeatureTable fontFeatureTable { get; internal set; } // 0x00389260-0x00389270 0x00389270-0x00389280
		public List<TMP_FontAsset> fallbackFontAssetTable { get; set; } // 0x00389280-0x00389290 0x00389290-0x003892A0
		public FontAssetCreationSettings creationSettings { get; set; } // 0x003892A0-0x003892F0 0x003892F0-0x00389340
		public TMP_FontWeightPair[] fontWeightTable { get; internal set; } // 0x00389340-0x00389350 0x00389350-0x00389360

		// Nested types
		[Serializable]
		private sealed class <>c // TypeDefIndex: 2747
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static Func<TMP_Character, uint> <>9__111_0; // 0x08
			public static Func<Glyph, uint> <>9__112_0; // 0x10

			// Constructors
			static <>c(); // 0x00AC6690-0x00AC66D0
			public <>c(); // 0x00AC66D0-0x00AC66E0

			// Methods
			internal uint <SortCharacterTable>b__111_0(TMP_Character c); // 0x00AC66E0-0x00AC66F0
			internal uint <SortGlyphTable>b__112_0(Glyph c); // 0x00AC66F0-0x00AC6700
		}

		// Constructors
		public TMP_FontAsset(); // 0x0038FCF0-0x00390070
		static TMP_FontAsset(); // 0x00390070-0x003901B0

		// Methods
		public static TMP_FontAsset CreateFontAsset(Font font); // 0x00389360-0x003893D0
		public static TMP_FontAsset CreateFontAsset(Font font, int samplingPointSize, int atlasPadding, GlyphRenderMode renderMode, int atlasWidth, int atlasHeight, AtlasPopulationMode atlasPopulationMode = AtlasPopulationMode.Dynamic /* Metadata: 0x0015A9D6 */, bool enableMultiAtlasSupport = true /* Metadata: 0x0015A9DA */); // 0x003893D0-0x00389B10
		private void Awake(); // 0x00389B10-0x00389C20
		public void ReadFontAssetDefinition(); // 0x00387540-0x00387810
		internal void InitializeDictionaryLookupTables(); // 0x00389C20-0x00389C40
		internal void InitializeGlyphLookupDictionary(); // 0x00388290-0x003884A0
		internal void InitializeCharacterLookupDictionary(); // 0x003884A0-0x00388640
		internal void InitializeGlyphPaidAdjustmentRecordsLookupDictionary(); // 0x00388640-0x003887D0
		internal void AddSynthesizedCharactersAndFaceMetrics(); // 0x003887D0-0x00388A10
		private void AddSynthesizedCharacter(uint unicode, bool addImmediately = false /* Metadata: 0x0015A9DB */); // 0x00388A10-0x00388C70
		internal void SortCharacterTable(); // 0x00389C40-0x00389D80
		internal void SortGlyphTable(); // 0x00389D80-0x00389EC0
		internal void SortFontFeatureTable(); // 0x00389EC0-0x00389EE0
		internal void SortAllTables(); // 0x0038A0D0-0x0038A100
		public bool HasCharacter(int character); // 0x0038A100-0x0038A160
		public bool HasCharacter(char character, bool searchFallbacks = false /* Metadata: 0x0015A9DC */, bool tryAddCharacter = false /* Metadata: 0x0015A9DD */); // 0x0038A160-0x0038A900
		private bool HasCharacter_Internal(uint character, bool searchFallbacks = false /* Metadata: 0x0015A9DE */, bool tryAddCharacter = false /* Metadata: 0x0015A9DF */); // 0x0038B390-0x0038B660
		public bool HasCharacters(string text, out List<char> missingCharacters); // 0x0038BA10-0x0038BBA0
		public bool HasCharacters(string text, out uint[] missingCharacters, bool searchFallbacks = false /* Metadata: 0x0015A9E0 */, bool tryAddCharacter = false /* Metadata: 0x0015A9E1 */); // 0x0038BBA0-0x0038C4C0
		public bool HasCharacters(string text); // 0x0038C4C0-0x0038C5D0
		public static string GetCharacters(TMP_FontAsset fontAsset); // 0x0038C5D0-0x0038C6A0
		public static int[] GetCharactersArray(TMP_FontAsset fontAsset); // 0x0038C6A0-0x0038C760
		internal uint GetGlyphIndex(uint unicode); // 0x0038C760-0x0038C880
		internal static void RegisterFontAssetForFontFeatureUpdate(TMP_FontAsset fontAsset); // 0x0038B660-0x0038B750
		internal static void UpdateFontFeaturesForFontAssetsInQueue(); // 0x0038C880-0x0038CA10
		internal static void RegisterFontAssetForAtlasTextureUpdate(TMP_FontAsset fontAsset); // 0x0038CE00-0x0038CEF0
		internal static void UpdateAtlasTexturesForFontAssetsInQueue(); // 0x0038CEF0-0x0038D070
		public bool TryAddCharacters(uint[] unicodes, bool includeFontFeatures = false /* Metadata: 0x0015A9E2 */); // 0x0038D080-0x0038D0A0
		public bool TryAddCharacters(uint[] unicodes, out uint[] missingUnicodes, bool includeFontFeatures = false /* Metadata: 0x0015A9E3 */); // 0x0038D0A0-0x0038DC50
		public bool TryAddCharacters(string characters, bool includeFontFeatures = false /* Metadata: 0x0015A9E4 */); // 0x0038DFA0-0x0038DFC0
		public bool TryAddCharacters(string characters, out string missingCharacters, bool includeFontFeatures = false /* Metadata: 0x0015A9E5 */); // 0x0038DFC0-0x0038EB20
		internal bool TryAddCharacterInternal(uint unicode, out TMP_Character character); // 0x0038A900-0x0038B390
		internal bool TryGetCharacter_and_QueueRenderToTexture(uint unicode, out TMP_Character character); // 0x0038EB20-0x0038EFD0
		internal void TryAddGlyphsToAtlasTextures(); // 0x0038D070-0x0038D080
		private bool TryAddGlyphsToNewAtlasTexture(); // 0x0038DC50-0x0038DFA0
		private void SetupNewAtlasTexture(); // 0x0038B750-0x0038BA10
		internal void UpdateAtlasTexture(); // 0x0038EFD0-0x0038F1B0
		internal void UpdateGlyphAdjustmentRecords(); // 0x0038CA10-0x0038CDA0
		internal void UpdateGlyphAdjustmentRecords(uint[] glyphIndexes); // 0x0038F240-0x0038F540
		private void CopyListDataToArray<T>(List<T> srcList, ref T[] dstArray);
		public void ClearFontAssetData(bool setAtlasSizeToZero = false /* Metadata: 0x0015A9E6 */); // 0x0038F540-0x0038F570
		internal void UpdateFontAssetData(); // 0x0038FB90-0x0038FCC0
		internal void ClearFontAssetTables(); // 0x0038F570-0x0038F710
		internal void ClearAtlasTextures(bool setAtlasSizeToZero = false /* Metadata: 0x0015A9E7 */); // 0x0038F710-0x0038FB90
		internal void UpgradeFontAsset(); // 0x00387810-0x00388290
		private void UpgradeGlyphAdjustmentTableToFontFeatureTable(); // 0x00388C70-0x00388FC0
	}

	[Serializable]
	public class FaceInfo_Legacy // TypeDefIndex: 2748
	{
		// Fields
		public string Name; // 0x10
		public float PointSize; // 0x18
		public float Scale; // 0x1C
		public int CharacterCount; // 0x20
		public float LineHeight; // 0x24
		public float Baseline; // 0x28
		public float Ascender; // 0x2C
		public float CapHeight; // 0x30
		public float Descender; // 0x34
		public float CenterLine; // 0x38
		public float SuperscriptOffset; // 0x3C
		public float SubscriptOffset; // 0x40
		public float SubSize; // 0x44
		public float Underline; // 0x48
		public float UnderlineThickness; // 0x4C
		public float strikethrough; // 0x50
		public float strikethroughThickness; // 0x54
		public float TabWidth; // 0x58
		public float Padding; // 0x5C
		public float AtlasWidth; // 0x60
		public float AtlasHeight; // 0x64

		// Constructors
		public FaceInfo_Legacy(); // 0x0037CE50-0x0037CE60
	}

	[Serializable]
	public class TMP_Glyph : TMP_TextElement_Legacy // TypeDefIndex: 2749
	{
		// Constructors
		public TMP_Glyph(); // 0x00390E00-0x00390E60
	}

	[Serializable]
	public struct FontAssetCreationSettings // TypeDefIndex: 2750
	{
		// Fields
		public string sourceFontFileName; // 0x00
		public string sourceFontFileGUID; // 0x08
		public int pointSizeSamplingMode; // 0x10
		public int pointSize; // 0x14
		public int padding; // 0x18
		public int packingMode; // 0x1C
		public int atlasWidth; // 0x20
		public int atlasHeight; // 0x24
		public int characterSetSelectionMode; // 0x28
		public string characterSequence; // 0x30
		public string referencedFontAssetGUID; // 0x38
		public string referencedTextAssetGUID; // 0x40
		public int fontStyle; // 0x48
		public float fontStyleModifier; // 0x4C
		public int renderMode; // 0x50
		public bool includeFontFeatures; // 0x54
	}

	[Serializable]
	public struct TMP_FontWeightPair // TypeDefIndex: 2751
	{
		// Fields
		public TMP_FontAsset regularTypeface; // 0x00
		public TMP_FontAsset italicTypeface; // 0x08
	}

	[Serializable]
	public struct GlyphValueRecord_Legacy // TypeDefIndex: 2752
	{
		// Fields
		public float xPlacement; // 0x00
		public float yPlacement; // 0x04
		public float xAdvance; // 0x08
		public float yAdvance; // 0x0C
	}

	[Serializable]
	public class KerningPair // TypeDefIndex: 2753
	{
		// Fields
		[FormerlySerializedAs] // 0x00253C10-0x00253C30
		[SerializeField] // 0x00253C10-0x00253C30
		private uint m_FirstGlyph; // 0x10
		[SerializeField] // 0x00253C30-0x00253C40
		private GlyphValueRecord_Legacy m_FirstGlyphAdjustments; // 0x14
		[FormerlySerializedAs] // 0x00253C40-0x00253C60
		[SerializeField] // 0x00253C40-0x00253C60
		private uint m_SecondGlyph; // 0x24
		[SerializeField] // 0x00253C60-0x00253C70
		private GlyphValueRecord_Legacy m_SecondGlyphAdjustments; // 0x28
		[FormerlySerializedAs] // 0x00253C70-0x00253C90
		public float xOffset; // 0x38
		internal static KerningPair empty; // 0x00
		[SerializeField] // 0x00253C90-0x00253CA0
		private bool m_IgnoreSpacingAdjustments; // 0x3C

		// Properties
		public uint firstGlyph { get; } // 0x0037D4B0-0x0037D4C0
		public GlyphValueRecord_Legacy firstGlyphAdjustments { get; } // 0x0037D4C0-0x0037D4D0
		public uint secondGlyph { get; } // 0x0037D4D0-0x0037D4E0
		public GlyphValueRecord_Legacy secondGlyphAdjustments { get; } // 0x0037D4E0-0x0037D4F0

		// Constructors
		public KerningPair(); // 0x0037D4F0-0x0037D510
		public KerningPair(uint firstGlyph, GlyphValueRecord_Legacy firstGlyphAdjustments, uint secondGlyph, GlyphValueRecord_Legacy secondGlyphAdjustments); // 0x0037D510-0x0037D530
		static KerningPair(); // 0x0037D530-0x0037D590
	}

	[Serializable]
	public class KerningTable // TypeDefIndex: 2754
	{
		// Fields
		public List<KerningPair> kerningPairs; // 0x10

		// Constructors
		public KerningTable(); // 0x0037D590-0x0037D660
	}

	public class TMP_FontAssetUtilities // TypeDefIndex: 2755
	{
		// Fields
		private static readonly TMP_FontAssetUtilities s_Instance; // 0x00
		private static List<int> k_SearchedFontAssets; // 0x08

		// Constructors
		static TMP_FontAssetUtilities(); // 0x003901B0-0x003901F0
		public TMP_FontAssetUtilities(); // 0x003901F0-0x00390200

		// Methods
		public static TMP_Character GetCharacterFromFontAsset(uint unicode, TMP_FontAsset sourceFontAsset, bool includeFallbacks, FontStyles fontStyle, FontWeight fontWeight, out bool isAlternativeTypeface, out TMP_FontAsset fontAsset); // 0x00390200-0x00390370
		private static TMP_Character GetCharacterFromFontAsset_Internal(uint unicode, TMP_FontAsset sourceFontAsset, bool includeFallbacks, FontStyles fontStyle, FontWeight fontWeight, out bool isAlternativeTypeface, out TMP_FontAsset fontAsset); // 0x00390370-0x003909A0
		public static TMP_Character GetCharacterFromFontAssets(uint unicode, List<TMP_FontAsset> fontAssets, bool includeFallbacks, FontStyles fontStyle, FontWeight fontWeight, out bool isAlternativeTypeface, out TMP_FontAsset fontAsset); // 0x003909A0-0x00390C90
	}

	[Serializable]
	public class TMP_FontFeatureTable // TypeDefIndex: 2756
	{
		// Fields
		[SerializeField] // 0x00253CA0-0x00253CB0
		internal List<TMP_GlyphPairAdjustmentRecord> m_GlyphPairAdjustmentRecords; // 0x10
		internal Dictionary<uint, TMP_GlyphPairAdjustmentRecord> m_GlyphPairAdjustmentRecordLookupDictionary; // 0x18

		// Properties
		public List<TMP_GlyphPairAdjustmentRecord> glyphPairAdjustmentRecords { get; } // 0x00390C90-0x00390E00

		// Nested types
		[Serializable]
		private sealed class <>c // TypeDefIndex: 2757
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static Func<TMP_GlyphPairAdjustmentRecord, uint> <>9__6_0; // 0x08
			public static Func<TMP_GlyphPairAdjustmentRecord, uint> <>9__6_1; // 0x10

			// Constructors
			static <>c(); // 0x00AC6700-0x00AC6740
			public <>c(); // 0x00AC6740-0x00AC6750

			// Methods
			internal uint <SortGlyphPairAdjustmentRecords>b__6_0(TMP_GlyphPairAdjustmentRecord s); // 0x00AC6750-0x00AC6760
			internal uint <SortGlyphPairAdjustmentRecords>b__6_1(TMP_GlyphPairAdjustmentRecord s); // 0x00AC6760-0x00AC6770
		}

		// Constructors
		public TMP_FontFeatureTable(); // 0x0038F1B0-0x0038F240

		// Methods
		public void SortGlyphPairAdjustmentRecords(); // 0x00389EE0-0x0038A0D0
	}

	public enum FontFeatureLookupFlags // TypeDefIndex: 2758
	{
		None = 0,
		IgnoreLigatures = 4,
		IgnoreSpacingAdjustments = 256
	}

	[Serializable]
	public struct TMP_GlyphValueRecord // TypeDefIndex: 2759
	{
		// Fields
		[SerializeField] // 0x00253CB0-0x00253CC0
		internal float m_XPlacement; // 0x00
		[SerializeField] // 0x00253CC0-0x00253CD0
		internal float m_YPlacement; // 0x04
		[SerializeField] // 0x00253CD0-0x00253CE0
		internal float m_XAdvance; // 0x08
		[SerializeField] // 0x00253CE0-0x00253CF0
		internal float m_YAdvance; // 0x0C

		// Properties
		public float xPlacement { get; } // 0x00256AB0-0x00256AC0
		public float yPlacement { get; } // 0x00256AC0-0x00256AD0
		public float xAdvance { get; } // 0x00256AD0-0x00256AE0
		public float yAdvance { get; } // 0x00256AE0-0x00256AF0

		// Constructors
		public TMP_GlyphValueRecord(float xPlacement, float yPlacement, float xAdvance, float yAdvance); // 0x00256AF0-0x00256B10
		internal TMP_GlyphValueRecord(GlyphValueRecord valueRecord); // 0x00256B10-0x00256B20

		// Methods
		public static TMP_GlyphValueRecord operator +(TMP_GlyphValueRecord a, TMP_GlyphValueRecord b); // 0x00390EF0-0x00390F00
	}

	[Serializable]
	public struct TMP_GlyphAdjustmentRecord // TypeDefIndex: 2760
	{
		// Fields
		[SerializeField] // 0x00253CF0-0x00253D00
		internal uint m_GlyphIndex; // 0x00
		[SerializeField] // 0x00253D00-0x00253D10
		internal TMP_GlyphValueRecord m_GlyphValueRecord; // 0x04

		// Properties
		public uint glyphIndex { get; } // 0x00256A50-0x00256A60
		public TMP_GlyphValueRecord glyphValueRecord { get; } // 0x00256A60-0x00256A70

		// Constructors
		public TMP_GlyphAdjustmentRecord(uint glyphIndex, TMP_GlyphValueRecord glyphValueRecord); // 0x00256A70-0x00256A80
		internal TMP_GlyphAdjustmentRecord(GlyphAdjustmentRecord adjustmentRecord); // 0x00256A80-0x00256AB0
	}

	[Serializable]
	public class TMP_GlyphPairAdjustmentRecord // TypeDefIndex: 2761
	{
		// Fields
		[SerializeField] // 0x00253D10-0x00253D20
		internal TMP_GlyphAdjustmentRecord m_FirstAdjustmentRecord; // 0x10
		[SerializeField] // 0x00253D20-0x00253D30
		internal TMP_GlyphAdjustmentRecord m_SecondAdjustmentRecord; // 0x24
		[SerializeField] // 0x00253D30-0x00253D40
		internal FontFeatureLookupFlags m_FeatureLookupFlags; // 0x38

		// Properties
		public TMP_GlyphAdjustmentRecord firstAdjustmentRecord { get; } // 0x00390E60-0x00390E80
		public TMP_GlyphAdjustmentRecord secondAdjustmentRecord { get; } // 0x00390E80-0x00390EA0
		public FontFeatureLookupFlags featureLookupFlags { get; } // 0x00390EA0-0x00390EF0

		// Constructors
		public TMP_GlyphPairAdjustmentRecord(TMP_GlyphAdjustmentRecord firstAdjustmentRecord, TMP_GlyphAdjustmentRecord secondAdjustmentRecord); // 0x0038FCC0-0x0038FCF0
		internal TMP_GlyphPairAdjustmentRecord(GlyphPairAdjustmentRecord glyphPairAdjustmentRecord); // 0x0038CDA0-0x0038CE00
	}

	public struct GlyphPairKey // TypeDefIndex: 2762
	{
		// Fields
		public uint firstGlyphIndex; // 0x00
		public uint secondGlyphIndex; // 0x04
		public uint key; // 0x08

		// Constructors
		public GlyphPairKey(uint firstGlyphIndex, uint secondGlyphIndex); // 0x00256660-0x00256670
		internal GlyphPairKey(TMP_GlyphPairAdjustmentRecord record); // 0x00256670-0x002566A0
	}

	public class TMP_InputField : Selectable, IUpdateSelectedHandler, IEventSystemHandler, IBeginDragHandler, IDragHandler, IEndDragHandler, IPointerClickHandler, ISubmitHandler, ICanvasElement, ILayoutElement, IScrollHandler // TypeDefIndex: 2763
	{
		// Fields
		protected TouchScreenKeyboard m_SoftKeyboard; // 0xF0
		private static readonly char[] kSeparators; // 0x00
		protected RectTransform m_RectTransform; // 0xF8
		[SerializeField] // 0x00253D40-0x00253D50
		protected RectTransform m_TextViewport; // 0x100
		protected RectMask2D m_TextComponentRectMask; // 0x108
		protected RectMask2D m_TextViewportRectMask; // 0x110
		private Rect m_CachedViewportRect; // 0x118
		[SerializeField] // 0x00253D50-0x00253D60
		protected TMP_Text m_TextComponent; // 0x128
		protected RectTransform m_TextComponentRectTransform; // 0x130
		[SerializeField] // 0x00253D60-0x00253D70
		protected Graphic m_Placeholder; // 0x138
		[SerializeField] // 0x00253D70-0x00253D80
		protected Scrollbar m_VerticalScrollbar; // 0x140
		[SerializeField] // 0x00253D80-0x00253D90
		protected TMP_ScrollbarEventHandler m_VerticalScrollbarEventHandler; // 0x148
		private bool m_IsDrivenByLayoutComponents; // 0x150
		[SerializeField] // 0x00253D90-0x00253DA0
		private LayoutGroup m_LayoutGroup; // 0x158
		private float m_ScrollPosition; // 0x160
		[SerializeField] // 0x00253DA0-0x00253DB0
		protected float m_ScrollSensitivity; // 0x164
		[SerializeField] // 0x00253DB0-0x00253DC0
		private ContentType m_ContentType; // 0x168
		[SerializeField] // 0x00253DC0-0x00253DD0
		private InputType m_InputType; // 0x16C
		[SerializeField] // 0x00253DD0-0x00253DE0
		private char m_AsteriskChar; // 0x170
		[SerializeField] // 0x00253DE0-0x00253DF0
		private TouchScreenKeyboardType m_KeyboardType; // 0x174
		[SerializeField] // 0x00253DF0-0x00253E00
		private LineType m_LineType; // 0x178
		[SerializeField] // 0x00253E00-0x00253E10
		private bool m_HideMobileInput; // 0x17C
		[SerializeField] // 0x00253E10-0x00253E20
		private bool m_HideSoftKeyboard; // 0x17D
		[SerializeField] // 0x00253E20-0x00253E30
		private CharacterValidation m_CharacterValidation; // 0x180
		[SerializeField] // 0x00253E30-0x00253E40
		private string m_RegexValue; // 0x188
		[SerializeField] // 0x00253E40-0x00253E50
		private float m_GlobalPointSize; // 0x190
		[SerializeField] // 0x00253E50-0x00253E60
		private int m_CharacterLimit; // 0x194
		[SerializeField] // 0x00253E60-0x00253E70
		private SubmitEvent m_OnEndEdit; // 0x198
		[SerializeField] // 0x00253E70-0x00253E80
		private SubmitEvent m_OnSubmit; // 0x1A0
		[SerializeField] // 0x00253E80-0x00253E90
		private SelectionEvent m_OnSelect; // 0x1A8
		[SerializeField] // 0x00253E90-0x00253EA0
		private SelectionEvent m_OnDeselect; // 0x1B0
		[SerializeField] // 0x00253EA0-0x00253EB0
		private TextSelectionEvent m_OnTextSelection; // 0x1B8
		[SerializeField] // 0x00253EB0-0x00253EC0
		private TextSelectionEvent m_OnEndTextSelection; // 0x1C0
		[SerializeField] // 0x00253EC0-0x00253ED0
		private OnChangeEvent m_OnValueChanged; // 0x1C8
		[SerializeField] // 0x00253ED0-0x00253EE0
		private TouchScreenKeyboardEvent m_OnTouchScreenKeyboardStatusChanged; // 0x1D0
		[SerializeField] // 0x00253EE0-0x00253EF0
		private OnValidateInput m_OnValidateInput; // 0x1D8
		[SerializeField] // 0x00253EF0-0x00253F00
		private Color m_CaretColor; // 0x1E0
		[SerializeField] // 0x00253F00-0x00253F10
		private bool m_CustomCaretColor; // 0x1F0
		[SerializeField] // 0x00253F10-0x00253F20
		private Color m_SelectionColor; // 0x1F4
		[SerializeField] // 0x00253F20-0x00253F30
		protected string m_Text; // 0x208
		[SerializeField] // 0x00253F30-0x00253F40
		private float m_CaretBlinkRate; // 0x210
		[SerializeField] // 0x00253F40-0x00253F50
		private int m_CaretWidth; // 0x214
		[SerializeField] // 0x00253F50-0x00253F60
		private bool m_ReadOnly; // 0x218
		[SerializeField] // 0x00253F60-0x00253F70
		private bool m_RichText; // 0x219
		protected int m_StringPosition; // 0x21C
		protected int m_StringSelectPosition; // 0x220
		protected int m_CaretPosition; // 0x224
		protected int m_CaretSelectPosition; // 0x228
		private RectTransform caretRectTrans; // 0x230
		protected UIVertex[] m_CursorVerts; // 0x238
		private CanvasRenderer m_CachedInputRenderer; // 0x240
		private Vector2 m_LastPosition; // 0x248
		[NonSerialized]
		protected Mesh m_Mesh; // 0x250
		private bool m_AllowInput; // 0x258
		private bool m_ShouldActivateNextUpdate; // 0x259
		private bool m_UpdateDrag; // 0x25A
		private bool m_DragPositionOutOfBounds; // 0x25B
		private const float kHScrollSpeed = 0.05f; // Metadata: 0x0015A9F6
		private const float kVScrollSpeed = 0.1f; // Metadata: 0x0015A9FA
		protected bool m_CaretVisible; // 0x25C
		private Coroutine m_BlinkCoroutine; // 0x260
		private float m_BlinkStartTime; // 0x268
		private Coroutine m_DragCoroutine; // 0x270
		private string m_OriginalText; // 0x278
		private bool m_WasCanceled; // 0x280
		private bool m_HasDoneFocusTransition; // 0x281
		private WaitForSecondsRealtime m_WaitForSecondsRealtime; // 0x288
		private bool m_PreventCallback; // 0x290
		private bool m_TouchKeyboardAllowsInPlaceEditing; // 0x291
		private bool m_IsTextComponentUpdateRequired; // 0x292
		private bool m_IsScrollbarUpdateRequired; // 0x293
		private bool m_IsUpdatingScrollbarValues; // 0x294
		private bool m_isLastKeyBackspace; // 0x295
		private float m_PointerDownClickStartTime; // 0x298
		private float m_KeyDownStartTime; // 0x29C
		private float m_DoubleClickDelay; // 0x2A0
		private const string kEmailSpecialCharacters = "!#$%&\'*+-/=?^_`{|}~"; // Metadata: 0x0015A9FE
		private bool m_IsCompositionActive; // 0x2A4
		private bool m_ShouldUpdateIMEWindowPosition; // 0x2A5
		private int m_PreviousIMEInsertionLine; // 0x2A8
		[SerializeField] // 0x00253F70-0x00253F80
		protected TMP_FontAsset m_GlobalFontAsset; // 0x2B0
		[SerializeField] // 0x00253F80-0x00253F90
		protected bool m_OnFocusSelectAll; // 0x2B8
		protected bool m_isSelectAll; // 0x2B9
		[SerializeField] // 0x00253F90-0x00253FA0
		protected bool m_ResetOnDeActivation; // 0x2BA
		private bool m_SelectionStillActive; // 0x2BB
		private bool m_ReleaseSelection; // 0x2BC
		private GameObject m_PreviouslySelectedObject; // 0x2C0
		[SerializeField] // 0x00253FA0-0x00253FB0
		private bool m_RestoreOriginalTextOnEscape; // 0x2C8
		[SerializeField] // 0x00253FB0-0x00253FC0
		protected bool m_isRichTextEditingAllowed; // 0x2C9
		[SerializeField] // 0x00253FC0-0x00253FD0
		protected int m_LineLimit; // 0x2CC
		[SerializeField] // 0x00253FD0-0x00253FE0
		protected TMP_InputValidator m_InputValidator; // 0x2D0
		private bool m_isSelected; // 0x2D8
		private bool m_IsStringPositionDirty; // 0x2D9
		private bool m_IsCaretPositionDirty; // 0x2DA
		private bool m_forceRectTransformAdjustment; // 0x2DB
		private Event m_ProcessingEvent; // 0x2E0

		// Properties
		private BaseInput inputSystem { get; } // 0x00390F00-0x00391010
		private string compositionString { get; } // 0x00391010-0x00391160
		private int compositionLength { get; } // 0x00391160-0x00391190
		protected Mesh mesh { get; } // 0x003916E0-0x00391800
		public bool shouldHideMobileInput { get; set; } // 0x00391800-0x00391870 0x00391870-0x00391970
		public bool shouldHideSoftKeyboard { get; set; } // 0x00391970-0x003919F0 0x003919F0-0x00391C40
		public string text { get; set; } // 0x00391CA0-0x00391CB0 0x00391CB0-0x00391CC0
		public bool isFocused { get; } // 0x00394080-0x00394090
		public float caretBlinkRate { get; set; } // 0x00394090-0x003940A0 0x003940A0-0x00394210
		public int caretWidth { get; set; } // 0x003942A0-0x003942B0 0x003942B0-0x003943F0
		public RectTransform textViewport { get; set; } // 0x00394490-0x003944A0 0x003944A0-0x00394510
		public TMP_Text textComponent { get; set; } // 0x00394510-0x00394520 0x00394520-0x00394590
		public Graphic placeholder { get; set; } // 0x00394590-0x003945A0 0x003945A0-0x00394610
		public Scrollbar verticalScrollbar { get; set; } // 0x00394610-0x00394620 0x00394620-0x003948A0
		public float scrollSensitivity { get; set; } // 0x003948A0-0x003948B0 0x003948B0-0x00394A30
		public Color caretColor { get; set; } // 0x00394A30-0x00394A70 0x00394A70-0x00394B60
		public bool customCaretColor { get; set; } // 0x00394B60-0x00394B70 0x00394B70-0x00394C20
		public Color selectionColor { get; set; } // 0x00394C20-0x00394C40 0x00394C40-0x00394D30
		public SubmitEvent onEndEdit { get; set; } // 0x00394D30-0x00394D40 0x00394D40-0x00394DB0
		public SubmitEvent onSubmit { get; set; } // 0x00394DB0-0x00394DC0 0x00394DC0-0x00394E30
		public SelectionEvent onSelect { get; set; } // 0x00394E30-0x00394E40 0x00394E40-0x00394EB0
		public SelectionEvent onDeselect { get; set; } // 0x00394EB0-0x00394EC0 0x00394EC0-0x00394F30
		public TextSelectionEvent onTextSelection { get; set; } // 0x00394F30-0x00394F40 0x00394F40-0x00394FB0
		public TextSelectionEvent onEndTextSelection { get; set; } // 0x00394FB0-0x00394FC0 0x00394FC0-0x00395030
		public OnChangeEvent onValueChanged { get; set; } // 0x00395030-0x00395040 0x00395040-0x003950B0
		public TouchScreenKeyboardEvent onTouchScreenKeyboardStatusChanged { get; set; } // 0x003950B0-0x003950C0 0x003950C0-0x00395130
		public OnValidateInput onValidateInput { get; set; } // 0x00395130-0x00395140 0x00395140-0x003951B0
		public int characterLimit { get; set; } // 0x003951B0-0x003951C0 0x003951C0-0x003952F0
		public float pointSize { get; set; } // 0x003952F0-0x00395300 0x00395300-0x00395430
		public TMP_FontAsset fontAsset { get; set; } // 0x00395660-0x00395670 0x00395670-0x003956F0
		public bool onFocusSelectAll { get; set; } // 0x00395840-0x00395850 0x00395850-0x00395860
		public bool resetOnDeActivation { get; set; } // 0x00395860-0x00395870 0x00395870-0x00395880
		public bool restoreOriginalTextOnEscape { get; set; } // 0x00395880-0x00395890 0x00395890-0x003958A0
		public bool isRichTextEditingAllowed { get; set; } // 0x003958A0-0x003958B0 0x003958B0-0x003958C0
		public ContentType contentType { get; set; } // 0x003958C0-0x003958D0 0x003958D0-0x00395A90
		public LineType lineType { get; set; } // 0x00395B70-0x00395B80 0x00395B80-0x00395CD0
		public int lineLimit { get; set; } // 0x00395D20-0x00395D30 0x00395D30-0x00395DF0
		public InputType inputType { get; set; } // 0x00395DF0-0x00395E00 0x00395E00-0x00395EF0
		public TouchScreenKeyboardType keyboardType { get; set; } // 0x00395F10-0x00395F20 0x00395F20-0x00396010
		public CharacterValidation characterValidation { get; set; } // 0x00396010-0x00396020 0x00396020-0x00396110
		public TMP_InputValidator inputValidator { get; set; } // 0x00396110-0x00396120 0x00396120-0x003961A0
		public bool readOnly { get; set; } // 0x003961C0-0x003961D0 0x003961D0-0x003961E0
		public bool richText { get; set; } // 0x003961E0-0x003961F0 0x003961F0-0x00396360
		public bool multiLine { get; } // 0x003964D0-0x003964E0
		public char asteriskChar { get; set; } // 0x003964E0-0x003964F0 0x003964F0-0x003965B0
		public bool wasCanceled { get; } // 0x003965B0-0x003965C0
		protected int caretPositionInternal { get; set; } // 0x00396630-0x00396660 0x00396660-0x003966A0
		protected int stringPositionInternal { get; set; } // 0x003966A0-0x003966D0 0x003966D0-0x00396700
		protected int caretSelectPositionInternal { get; set; } // 0x00396700-0x00396730 0x00396730-0x00396770
		protected int stringSelectPositionInternal { get; set; } // 0x00396770-0x003967A0 0x003967A0-0x003967D0
		private new bool hasSelection { get; } // 0x003967D0-0x00396830
		public int caretPosition { get; set; } // 0x00396830-0x00396860 0x00396860-0x00396950
		public int selectionAnchorPosition { get; set; } // 0x00396A30-0x00396A60 0x00396950-0x003969C0
		public int selectionFocusPosition { get; set; } // 0x00396A60-0x00396A90 0x003969C0-0x00396A30
		public int stringPosition { get; set; } // 0x00396A90-0x00396AC0 0x00396AC0-0x00396B80
		public int selectionStringAnchorPosition { get; set; } // 0x00396C40-0x00396C70 0x00396B80-0x00396BE0
		public int selectionStringFocusPosition { get; set; } // 0x00396C70-0x00396CA0 0x00396BE0-0x00396C40
		private static string clipboard { get; set; } // 0x00399340-0x00399390 0x00399390-0x003993E0
		public virtual float minWidth { get; } // 0x003A59C0-0x003A59D0
		public virtual float preferredWidth { get; } // 0x003A59D0-0x003A5D50
		public virtual float flexibleWidth { get; } // 0x003A5D50-0x003A5D60
		public virtual float minHeight { get; } // 0x003A5D60-0x003A5D70
		public virtual float preferredHeight { get; } // 0x003A5D70-0x003A60F0
		public virtual float flexibleHeight { get; } // 0x003A60F0-0x003A6100
		public virtual int layoutPriority { get; } // 0x003A6100-0x003A6110
		Transform ICanvasElement.transform { get; } // 0x003A61C0-0x003A6210

		// Nested types
		public enum ContentType // TypeDefIndex: 2764
		{
			Standard = 0,
			Autocorrected = 1,
			IntegerNumber = 2,
			DecimalNumber = 3,
			Alphanumeric = 4,
			Name = 5,
			EmailAddress = 6,
			Password = 7,
			Pin = 8,
			Custom = 9
		}

		public enum InputType // TypeDefIndex: 2765
		{
			Standard = 0,
			AutoCorrect = 1,
			Password = 2
		}

		public enum CharacterValidation // TypeDefIndex: 2766
		{
			None = 0,
			Digit = 1,
			Integer = 2,
			Decimal = 3,
			Alphanumeric = 4,
			Name = 5,
			Regex = 6,
			EmailAddress = 7,
			CustomValidator = 8
		}

		public enum LineType // TypeDefIndex: 2767
		{
			SingleLine = 0,
			MultiLineSubmit = 1,
			MultiLineNewline = 2
		}

		public delegate char OnValidateInput(string text, int charIndex, char addedChar); // TypeDefIndex: 2768; 0x00AC6C40-0x00AC7180

		[Serializable]
		public class SubmitEvent : UnityEvent<string> // TypeDefIndex: 2769
		{
			// Constructors
			public SubmitEvent(); // 0x00AC7280-0x00AC72C0
		}

		[Serializable]
		public class OnChangeEvent : UnityEvent<string> // TypeDefIndex: 2770
		{
			// Constructors
			public OnChangeEvent(); // 0x00AC6BF0-0x00AC6C30
		}

		[Serializable]
		public class SelectionEvent : UnityEvent<string> // TypeDefIndex: 2771
		{
			// Constructors
			public SelectionEvent(); // 0x00AC7240-0x00AC7280
		}

		[Serializable]
		public class TextSelectionEvent : UnityEvent<string, int, int> // TypeDefIndex: 2772
		{
			// Constructors
			public TextSelectionEvent(); // 0x00AC72C0-0x00AC7300
		}

		[Serializable]
		public class TouchScreenKeyboardEvent : UnityEvent<TouchScreenKeyboard.Status> // TypeDefIndex: 2773
		{
			// Constructors
			public TouchScreenKeyboardEvent(); // 0x00AC7300-0x00AC7340
		}

		protected enum EditState // TypeDefIndex: 2774
		{
			Continue = 0,
			Finish = 1
		}

		private sealed class <CaretBlink>d__277 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2775
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public TMP_InputField <>4__this; // 0x20

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00254950-0x00254960 */ get; } // 0x00AC6940-0x00AC6950
			object IEnumerator.Current { [DebuggerHidden] /* 0x00254960-0x00254970 */ get; } // 0x00AC6950-0x00AC6960

			// Constructors
			[DebuggerHidden] // 0x00254930-0x00254940
			public <CaretBlink>d__277(int <>1__state); // 0x00AC6770-0x00AC6780

			// Methods
			[DebuggerHidden] // 0x00254940-0x00254950
			void IDisposable.Dispose(); // 0x00AC6780-0x00AC6790
			private bool MoveNext(); // 0x00AC6790-0x00AC6940
		}

		private sealed class <MouseDragOutsideRect>d__295 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2776
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public TMP_InputField <>4__this; // 0x20
			public PointerEventData eventData; // 0x28

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00254990-0x002549A0 */ get; } // 0x00AC6BD0-0x00AC6BE0
			object IEnumerator.Current { [DebuggerHidden] /* 0x002549A0-0x002549B0 */ get; } // 0x00AC6BE0-0x00AC6BF0

			// Constructors
			[DebuggerHidden] // 0x00254970-0x00254980
			public <MouseDragOutsideRect>d__295(int <>1__state); // 0x00AC6960-0x00AC6970

			// Methods
			[DebuggerHidden] // 0x00254980-0x00254990
			void IDisposable.Dispose(); // 0x00AC6970-0x00AC6980
			private bool MoveNext(); // 0x00AC6980-0x00AC6BD0
		}

		// Constructors
		protected TMP_InputField(); // 0x00391190-0x00391550
		static TMP_InputField(); // 0x003A6110-0x003A61C0

		// Methods
		private bool isKeyboardUsingEvents(); // 0x00391C40-0x00391CA0
		public void SetTextWithoutNotify(string input); // 0x00394020-0x00394030
		private void SetText(string value, bool sendCallback = true /* Metadata: 0x0015A9F4 */); // 0x00391CC0-0x00391EA0
		protected void ClampStringPos(ref int pos); // 0x003965C0-0x003965F0
		protected void ClampCaretPos(ref int pos); // 0x003965F0-0x00396630
		protected override void OnEnable(); // 0x00396CA0-0x00397A00
		protected override void OnDisable(); // 0x00397A10-0x00398010
		private void ON_TEXT_CHANGED(UnityEngine.Object obj); // 0x00398700-0x00398980
		private IEnumerator CaretBlink(); // 0x003989F0-0x00398A40
		private void SetCaretVisible(); // 0x00392CB0-0x00392D90
		private void SetCaretActive(); // 0x00394210-0x003942A0
		protected void OnFocus(); // 0x00398A40-0x00398A90
		protected void SelectAll(); // 0x00398A90-0x00398AE0
		public void MoveTextEnd(bool shift); // 0x00398AE0-0x00398C30
		public void MoveTextStart(bool shift); // 0x00398CA0-0x00398E50
		public void MoveToEndOfLine(bool shift, bool ctrl); // 0x00398E50-0x003990A0
		public void MoveToStartOfLine(bool shift, bool ctrl); // 0x003990A0-0x00399340
		private bool InPlaceEditing(); // 0x003993E0-0x003996F0
		private void UpdateStringPositionFromKeyboard(); // 0x003996F0-0x003999F0
		protected virtual void LateUpdate(); // 0x003999F0-0x0039A930
		private bool MayDrag(PointerEventData eventData); // 0x0039BD70-0x0039BF90
		public virtual void OnBeginDrag(PointerEventData eventData); // 0x0039BF90-0x0039BFB0
		public virtual void OnDrag(PointerEventData eventData); // 0x0039BFB0-0x0039C440
		private IEnumerator MouseDragOutsideRect(PointerEventData eventData); // 0x0039C440-0x0039C4A0
		public virtual void OnEndDrag(PointerEventData eventData); // 0x0039C4A0-0x0039C4C0
		public override void OnPointerDown(PointerEventData eventData); // 0x0039C4C0-0x0039D090
		protected EditState KeyPressed(Event evt); // 0x0039D090-0x0039D720
		protected virtual bool IsValidChar(char c); // 0x003A1610-0x003A1630
		public void ProcessEvent(Event e); // 0x003A1630-0x003A1640
		public virtual void OnUpdateSelected(BaseEventData eventData); // 0x003A1640-0x003A1A00
		public virtual void OnScroll(PointerEventData eventData); // 0x003A1A50-0x003A1C40
		private string GetSelectedString(); // 0x0039E1D0-0x0039E2D0
		private int FindNextWordBegin(); // 0x003A1360-0x003A1460
		private void MoveRight(bool shift, bool ctrl); // 0x0039EA70-0x0039F220
		private int FindPrevWordBegin(); // 0x003A1460-0x003A1540
		private void MoveLeft(bool shift, bool ctrl); // 0x0039E2D0-0x0039EA70
		private int LineUpCharacterPosition(int originalPos, bool goToFirstChar); // 0x003A10B0-0x003A1360
		private int LineDownCharacterPosition(int originalPos, bool goToLastChar); // 0x003A0E10-0x003A10B0
		private int PageUpCharacterPosition(int originalPos, bool goToFirstChar); // 0x003A0A50-0x003A0E10
		private int PageDownCharacterPosition(int originalPos, bool goToLastChar); // 0x003A06C0-0x003A0A50
		private void MoveDown(bool shift); // 0x003A15E0-0x003A15F0
		private void MoveDown(bool shift, bool goToLastChar); // 0x0039F550-0x0039F8B0
		private void MoveUp(bool shift); // 0x003A15D0-0x003A15E0
		private void MoveUp(bool shift, bool goToFirstChar); // 0x0039F220-0x0039F550
		private void MovePageUp(bool shift); // 0x003A15F0-0x003A1600
		private void MovePageUp(bool shift, bool goToFirstChar); // 0x0039F8B0-0x0039FFA0
		private void MovePageDown(bool shift); // 0x003A1600-0x003A1610
		private void MovePageDown(bool shift, bool goToLastChar); // 0x0039FFA0-0x003A06C0
		private void Delete(); // 0x00392AE0-0x00392CB0
		private void DeleteKey(); // 0x0039DDB0-0x0039E1D0
		private void Backspace(); // 0x0039D720-0x0039DDB0
		protected virtual void Append(string input); // 0x003A1C40-0x003A1D40
		protected virtual void Append(char input); // 0x003A1D40-0x003A1EC0
		private void Insert(char c); // 0x003A1EC0-0x003A2060
		private void UpdateTouchKeyboardFromEditChanges(); // 0x003A1540-0x003A15D0
		private void SendOnValueChangedAndUpdateLabel(); // 0x0039BD20-0x0039BD70
		private void SendOnValueChanged(); // 0x00394030-0x00394080
		protected void SendOnEndEdit(); // 0x003A2060-0x003A20B0
		protected void SendOnSubmit(); // 0x003A1A00-0x003A1A50
		protected void SendOnFocus(); // 0x003A20B0-0x003A2100
		protected void SendOnFocusLost(); // 0x003A2100-0x003A2150
		protected void SendOnTextSelection(); // 0x003A2150-0x003A2210
		protected void SendOnEndTextSelection(); // 0x00398640-0x00398700
		protected void SendTouchScreenKeyboardStatusChanged(); // 0x0039BC80-0x0039BD20
		protected void UpdateLabel(); // 0x00392140-0x00392AE0
		private void UpdateScrollbar(); // 0x0039B200-0x0039B450
		private void OnScrollbarValueChange(float value); // 0x003A2210-0x003A2260
		private void UpdateMaskRegions(); // 0x00397A00-0x00397A10
		private void AdjustTextPositionRelativeToViewport(float relativePosition); // 0x00391EA0-0x00392140
		private int GetCaretPositionFromStringIndex(int stringIndex); // 0x00398980-0x003989F0
		private int GetMinCaretPositionFromStringIndex(int stringIndex); // 0x003A2260-0x003A22D0
		private int GetMaxCaretPositionFromStringIndex(int stringIndex); // 0x003A22D0-0x003A2340
		private int GetStringIndexFromCaretPosition(int caretPosition); // 0x00398C30-0x00398CA0
		public void ForceLabelUpdate(); // 0x003A2340-0x003A2350
		private void MarkGeometryAsDirty(); // 0x003943F0-0x00394490
		public virtual void Rebuild(CanvasUpdate update); // 0x003A2350-0x003A2360
		public virtual void LayoutComplete(); // 0x003A53E0-0x003A53F0
		public virtual void GraphicUpdateComplete(); // 0x003A53F0-0x003A5400
		private void UpdateGeometry(); // 0x003A2360-0x003A26E0
		private void AssignPositioningIfNeeded(); // 0x00392D90-0x00394020
		private void OnFillVBO(Mesh vbo); // 0x003A26E0-0x003A2C90
		private void GenerateCaret(VertexHelper vbo, Vector2 roundingOffset); // 0x003A2C90-0x003A37D0
		private void CreateCursorVerts(); // 0x003A5200-0x003A53E0
		private void GenerateHightlight(VertexHelper vbo, Vector2 roundingOffset); // 0x003A37D0-0x003A4050
		private void AdjustRectTransformRelativeToViewport(Vector2 startPosition, float height, bool isCharVisible); // 0x003A4050-0x003A5200
		protected char Validate(string text, int pos, char ch); // 0x0039B450-0x0039BC80
		public void ActivateInputField(); // 0x003A5400-0x003A5720
		private void ActivateInputFieldInternal(); // 0x0039A930-0x0039B200
		public override void OnSelect(BaseEventData eventData); // 0x003A5720-0x003A57F0
		public virtual void OnPointerClick(PointerEventData eventData); // 0x003A57F0-0x003A5810
		public void ReleaseSelection(); // 0x00398550-0x00398640
		public void DeactivateInputField(bool clearSelection = false /* Metadata: 0x0015A9F5 */); // 0x00398010-0x00398550
		public override void OnDeselect(BaseEventData eventData); // 0x003A5810-0x003A58F0
		public virtual void OnSubmit(BaseEventData eventData); // 0x003A58F0-0x003A5970
		private void EnforceContentType(); // 0x00395A90-0x00395B70
		private void SetTextComponentWrapMode(); // 0x00391550-0x003916E0
		private void SetTextComponentRichTextMode(); // 0x00396360-0x003964D0
		private void SetToCustomIfContentTypeIsNot(params /* 0x00254A70-0x00254A80 */ ContentType[] allowedContentTypes); // 0x00395CD0-0x00395D20
		private void SetToCustom(); // 0x00395EF0-0x00395F10
		private void SetToCustom(CharacterValidation characterValidation); // 0x003961A0-0x003961C0
		protected override void DoStateTransition(SelectionState state, bool instant); // 0x003A5970-0x003A59A0
		public virtual void CalculateLayoutInputHorizontal(); // 0x003A59A0-0x003A59B0
		public virtual void CalculateLayoutInputVertical(); // 0x003A59B0-0x003A59C0
		public void SetGlobalPointSize(float pointSize); // 0x00395430-0x00395660
		public void SetGlobalFontAsset(TMP_FontAsset fontAsset); // 0x003956F0-0x00395840
	}

	internal static class SetPropertyUtility // TypeDefIndex: 2777
	{
		// Methods
		public static bool SetColor(ref Color currentValue, Color newValue); // 0x0037E670-0x0037E6C0
		public static bool SetStruct<T>(ref T currentValue, T newValue)
			where T : struct;
		public static bool SetClass<T>(ref T currentValue, T newValue)
			where T : class;
	}

	[Serializable]
	public abstract class TMP_InputValidator : ScriptableObject // TypeDefIndex: 2778
	{
		// Constructors
		protected TMP_InputValidator(); // 0x00325730-0x00325820

		// Methods
		public abstract char Validate(ref string text, ref int pos, char ch);
	}

	public struct TMP_LineInfo // TypeDefIndex: 2779
	{
		// Fields
		internal int controlCharacterCount; // 0x00
		public int characterCount; // 0x04
		public int visibleCharacterCount; // 0x08
		public int spaceCount; // 0x0C
		public int wordCount; // 0x10
		public int firstCharacterIndex; // 0x14
		public int firstVisibleCharacterIndex; // 0x18
		public int lastCharacterIndex; // 0x1C
		public int lastVisibleCharacterIndex; // 0x20
		public float length; // 0x24
		public float lineHeight; // 0x28
		public float ascender; // 0x2C
		public float baseline; // 0x30
		public float descender; // 0x34
		public float maxAdvance; // 0x38
		public float width; // 0x3C
		public float marginLeft; // 0x40
		public float marginRight; // 0x44
		public HorizontalAlignmentOptions alignment; // 0x48
		public Extents lineExtents; // 0x4C
	}

	internal static class TMP_ListPool<T> // TypeDefIndex: 2780
	{
		// Fields
		private static readonly TMP_ObjectPool<List<T>> s_ListPool;

		// Nested types
		[Serializable]
		private sealed class <>c // TypeDefIndex: 2781
		{
			// Fields
			public static readonly <>c<T> <>9;

			// Constructors
			static <>c();
			public <>c();

			// Methods
			internal void <.cctor>b__3_0(List<T> l);
		}

		// Constructors
		static TMP_ListPool();

		// Methods
		public static List<T> Get();
		public static void Release(List<T> toRelease);
	}

	public static class TMP_MaterialManager // TypeDefIndex: 2782
	{
		// Fields
		private static List<MaskingMaterial> m_materialList; // 0x00
		private static Dictionary<long, FallbackMaterial> m_fallbackMaterials; // 0x08
		private static Dictionary<int, long> m_fallbackMaterialLookup; // 0x10
		private static List<FallbackMaterial> m_fallbackCleanupList; // 0x18
		private static bool isFallbackListDirty; // 0x20

		// Nested types
		private class FallbackMaterial // TypeDefIndex: 2783
		{
			// Fields
			public int baseID; // 0x10
			public Material baseMaterial; // 0x18
			public long fallbackID; // 0x20
			public Material fallbackMaterial; // 0x28
			public int count; // 0x30

			// Constructors
			public FallbackMaterial(); // 0x00AC7340-0x00AC7350
		}

		private class MaskingMaterial // TypeDefIndex: 2784
		{
			// Fields
			public Material baseMaterial; // 0x10
			public Material stencilMaterial; // 0x18
			public int count; // 0x20
			public int stencilID; // 0x24

			// Constructors
			public MaskingMaterial(); // 0x00AC7350-0x00AC7360
		}

		// Constructors
		static TMP_MaterialManager(); // 0x00325820-0x00325A70

		// Methods
		private static void OnPreRender(Camera cam); // 0x00325A70-0x00325AF0
		private static void OnPreRenderCanvas(); // 0x00325D40-0x00325DC0
		public static Material GetStencilMaterial(Material baseMaterial, int stencilID); // 0x00325DC0-0x00326250
		public static void ReleaseStencilMaterial(Material stencilMaterial); // 0x00326250-0x003264A0
		public static int GetStencilID(GameObject obj); // 0x003264A0-0x003269F0
		public static Material GetMaterialForRendering(MaskableGraphic graphic, Material baseMaterial); // 0x00326C80-0x00326EC0
		private static Transform FindRootSortOverrideCanvas(Transform start); // 0x003269F0-0x00326C80
		internal static Material GetFallbackMaterial(TMP_FontAsset fontAsset, Material sourceMaterial, int atlasIndex); // 0x00326EC0-0x003271B0
		public static Material GetFallbackMaterial(Material sourceMaterial, Material targetMaterial); // 0x003271B0-0x00327870
		public static void AddFallbackMaterialReference(Material targetMaterial); // 0x00327870-0x00327A70
		public static void CleanupFallbackMaterials(); // 0x00325AF0-0x00325D40
		public static void ReleaseFallbackMaterial(Material fallackMaterial); // 0x00327A70-0x00327D00
	}

	public enum VertexSortingOrder // TypeDefIndex: 2785
	{
		Normal = 0,
		Reverse = 1
	}

	public struct TMP_MeshInfo // TypeDefIndex: 2786
	{
		// Fields
		private static readonly Color32 s_DefaultColor; // 0x00
		private static readonly Vector3 s_DefaultNormal; // 0x04
		private static readonly Vector4 s_DefaultTangent; // 0x10
		private static readonly Bounds s_DefaultBounds; // 0x20
		public Mesh mesh; // 0x00
		public int vertexCount; // 0x08
		public Vector3[] vertices; // 0x10
		public Vector3[] normals; // 0x18
		public Vector4[] tangents; // 0x20
		public Vector2[] uvs0; // 0x28
		public Vector2[] uvs2; // 0x30
		public Color32[] colors32; // 0x38
		public int[] triangles; // 0x40
		public Material material; // 0x48

		// Constructors
		public TMP_MeshInfo(Mesh mesh, int size); // 0x002290C0-0x002290D0
		public TMP_MeshInfo(Mesh mesh, int size, bool isVolumetric); // 0x002290D0-0x002290E0
		static TMP_MeshInfo(); // 0x0032B030-0x0032B0F0

		// Methods
		public void ResizeMeshInfo(int size); // 0x002290E0-0x002290F0
		public void ResizeMeshInfo(int size, bool isVolumetric); // 0x002290F0-0x00229100
		public void Clear(bool uploadChanges); // 0x00229100-0x00229110
		public void ClearUnusedVertices(); // 0x00229110-0x00229140
		public void ClearUnusedVertices(int startIndex, bool updateMesh); // 0x00229140-0x00229150
		public void SortGeometry(VertexSortingOrder order); // 0x00229150-0x002291C0
		public void SwapVertexData(int src, int dst); // 0x002291C0-0x002291D0
	}

	internal class TMP_ObjectPool<T> // TypeDefIndex: 2787
		where T : new()
	{
		// Fields
		private readonly Stack<T> m_Stack;
		private readonly UnityAction<T> m_ActionOnGet;
		private readonly UnityAction<T> m_ActionOnRelease;
		private int <countAll>k__BackingField;

		// Properties
		public int countAll { get; private set; }

		// Constructors
		public TMP_ObjectPool(UnityAction<T> actionOnGet, UnityAction<T> actionOnRelease);

		// Methods
		public T Get();
		public void Release(T element);
	}

	public struct TMP_FontStyleStack // TypeDefIndex: 2788
	{
		// Fields
		public byte bold; // 0x00
		public byte italic; // 0x01
		public byte underline; // 0x02
		public byte strikethrough; // 0x03
		public byte highlight; // 0x04
		public byte superscript; // 0x05
		public byte subscript; // 0x06
		public byte uppercase; // 0x07
		public byte lowercase; // 0x08
		public byte smallcaps; // 0x09

		// Methods
		public void Clear(); // 0x002568A0-0x002568B0
		public byte Add(FontStyles style); // 0x002568B0-0x00256930
		public byte Remove(FontStyles style); // 0x00256930-0x00256A50
	}

	public struct TMP_RichTextTagStack<T> // TypeDefIndex: 2789
	{
		// Fields
		public T[] itemStack;
		public int index;
		private int m_Capacity;
		private T m_DefaultItem;
		private const int k_DefaultCapacity = 4; // Metadata: 0x0015AA89

		// Properties
		public T current { get; }

		// Constructors
		public TMP_RichTextTagStack(T[] tagStack);
		public TMP_RichTextTagStack(int capacity);

		// Methods
		public void Clear();
		public void SetDefault(T item);
		public void Add(T item);
		public T Remove();
		public void Push(T item);
		public T Pop();
		public T Peek();
		public T CurrentItem();
	}

	public enum TagValueType // TypeDefIndex: 2790
	{
		None = 0,
		NumericalValue = 1,
		StringValue = 2,
		ColorValue = 4
	}

	public enum TagUnitType // TypeDefIndex: 2791
	{
		Pixels = 0,
		FontUnits = 1,
		Percentage = 2
	}

	public class TMP_ScrollbarEventHandler : MonoBehaviour, IPointerClickHandler, IEventSystemHandler, ISelectHandler, IDeselectHandler // TypeDefIndex: 2792
	{
		// Fields
		public bool isSelected; // 0x18

		// Constructors
		public TMP_ScrollbarEventHandler(); // 0x0032B3B0-0x0032B3F0

		// Methods
		public void OnPointerClick(PointerEventData eventData); // 0x0032B2C0-0x0032B310
		public void OnSelect(BaseEventData eventData); // 0x0032B310-0x0032B360
		public void OnDeselect(BaseEventData eventData); // 0x0032B360-0x0032B3B0
	}

	[RequireComponent] // 0x00253750-0x00253790
	public class TMP_SelectionCaret : MaskableGraphic // TypeDefIndex: 2793
	{
		// Constructors
		public TMP_SelectionCaret(); // 0x0032B510-0x0032B520

		// Methods
		public override void Cull(Rect clipRect, bool validRect); // 0x0032B3F0-0x0032B500
		protected override void UpdateGeometry(); // 0x0032B500-0x0032B510
	}

	[Serializable]
	public class TMP_Settings : ScriptableObject // TypeDefIndex: 2794
	{
		// Fields
		private static TMP_Settings s_Instance; // 0x00
		[SerializeField] // 0x00253FE0-0x00253FF0
		private bool m_enableWordWrapping; // 0x18
		[SerializeField] // 0x00253FF0-0x00254000
		private bool m_enableKerning; // 0x19
		[SerializeField] // 0x00254000-0x00254010
		private bool m_enableExtraPadding; // 0x1A
		[SerializeField] // 0x00254010-0x00254020
		private bool m_enableTintAllSprites; // 0x1B
		[SerializeField] // 0x00254020-0x00254030
		private bool m_enableParseEscapeCharacters; // 0x1C
		[SerializeField] // 0x00254030-0x00254040
		private bool m_EnableRaycastTarget; // 0x1D
		[SerializeField] // 0x00254040-0x00254050
		private bool m_GetFontFeaturesAtRuntime; // 0x1E
		[SerializeField] // 0x00254050-0x00254060
		private int m_missingGlyphCharacter; // 0x20
		[SerializeField] // 0x00254060-0x00254070
		private bool m_warningsDisabled; // 0x24
		[SerializeField] // 0x00254070-0x00254080
		private TMP_FontAsset m_defaultFontAsset; // 0x28
		[SerializeField] // 0x00254080-0x00254090
		private string m_defaultFontAssetPath; // 0x30
		[SerializeField] // 0x00254090-0x002540A0
		private float m_defaultFontSize; // 0x38
		[SerializeField] // 0x002540A0-0x002540B0
		private float m_defaultAutoSizeMinRatio; // 0x3C
		[SerializeField] // 0x002540B0-0x002540C0
		private float m_defaultAutoSizeMaxRatio; // 0x40
		[SerializeField] // 0x002540C0-0x002540D0
		private Vector2 m_defaultTextMeshProTextContainerSize; // 0x44
		[SerializeField] // 0x002540D0-0x002540E0
		private Vector2 m_defaultTextMeshProUITextContainerSize; // 0x4C
		[SerializeField] // 0x002540E0-0x002540F0
		private bool m_autoSizeTextContainer; // 0x54
		[SerializeField] // 0x002540F0-0x00254100
		private List<TMP_FontAsset> m_fallbackFontAssets; // 0x58
		[SerializeField] // 0x00254100-0x00254110
		private bool m_matchMaterialPreset; // 0x60
		[SerializeField] // 0x00254110-0x00254120
		private TMP_SpriteAsset m_defaultSpriteAsset; // 0x68
		[SerializeField] // 0x00254120-0x00254130
		private string m_defaultSpriteAssetPath; // 0x70
		[SerializeField] // 0x00254130-0x00254140
		private bool m_enableEmojiSupport; // 0x78
		[SerializeField] // 0x00254140-0x00254150
		private string m_defaultColorGradientPresetsPath; // 0x80
		[SerializeField] // 0x00254150-0x00254160
		private TMP_StyleSheet m_defaultStyleSheet; // 0x88
		[SerializeField] // 0x00254160-0x00254170
		private string m_StyleSheetsResourcePath; // 0x90
		[SerializeField] // 0x00254170-0x00254180
		private TextAsset m_leadingCharacters; // 0x98
		[SerializeField] // 0x00254180-0x00254190
		private TextAsset m_followingCharacters; // 0xA0
		[SerializeField] // 0x00254190-0x002541A0
		private LineBreakingTable m_linebreakingRules; // 0xA8
		[SerializeField] // 0x002541A0-0x002541B0
		private bool m_UseModernHangulLineBreakingRules; // 0xB0

		// Properties
		public static string version { get; } // 0x0032B520-0x0032B550
		public static bool enableWordWrapping { get; } // 0x0032B550-0x0032B680
		public static bool enableKerning { get; } // 0x0032B7A0-0x0032B8D0
		public static bool enableExtraPadding { get; } // 0x0032B8D0-0x0032BA00
		public static bool enableTintAllSprites { get; } // 0x0032BA00-0x0032BB30
		public static bool enableParseEscapeCharacters { get; } // 0x0032BB30-0x0032BC60
		public static bool enableRaycastTarget { get; } // 0x0032BC60-0x0032BD90
		public static bool getFontFeaturesAtRuntime { get; } // 0x0032BD90-0x0032BEC0
		public static int missingGlyphCharacter { get; set; } // 0x0032BEC0-0x0032BFF0 0x0032BFF0-0x0032C130
		public static bool warningsDisabled { get; } // 0x0032C130-0x0032C260
		public static TMP_FontAsset defaultFontAsset { get; } // 0x0032C260-0x0032C390
		public static string defaultFontAssetPath { get; } // 0x0032C390-0x0032C4C0
		public static float defaultFontSize { get; } // 0x0032C4C0-0x0032C5F0
		public static float defaultTextAutoSizingMinRatio { get; } // 0x0032C5F0-0x0032C720
		public static float defaultTextAutoSizingMaxRatio { get; } // 0x0032C720-0x0032C850
		public static Vector2 defaultTextMeshProTextContainerSize { get; } // 0x0032C850-0x0032C980
		public static Vector2 defaultTextMeshProUITextContainerSize { get; } // 0x0032C980-0x0032CAB0
		public static bool autoSizeTextContainer { get; } // 0x0032CAB0-0x0032CBE0
		public static List<TMP_FontAsset> fallbackFontAssets { get; } // 0x0032CBE0-0x0032CD10
		public static bool matchMaterialPreset { get; } // 0x0032CD10-0x0032CE40
		public static TMP_SpriteAsset defaultSpriteAsset { get; } // 0x0032CE40-0x0032CF70
		public static string defaultSpriteAssetPath { get; } // 0x0032CF70-0x0032D0A0
		public static bool enableEmojiSupport { get; set; } // 0x0032D0A0-0x0032D1D0 0x0032D1D0-0x0032D310
		public static string defaultColorGradientPresetsPath { get; } // 0x0032D310-0x0032D440
		public static TMP_StyleSheet defaultStyleSheet { get; } // 0x0032D440-0x0032D570
		public static string styleSheetsResourcePath { get; } // 0x0032D570-0x0032D6A0
		public static TextAsset leadingCharacters { get; } // 0x0032D6A0-0x0032D7D0
		public static TextAsset followingCharacters { get; } // 0x0032D7D0-0x0032D900
		public static LineBreakingTable linebreakingRules { get; } // 0x0032D900-0x0032DB60
		public static bool useModernHangulLineBreakingRules { get; set; } // 0x0032DFA0-0x0032E0D0 0x0032E0D0-0x0032E210
		public static TMP_Settings instance { get; } // 0x0032B680-0x0032B7A0

		// Nested types
		public class LineBreakingTable // TypeDefIndex: 2795
		{
			// Fields
			public Dictionary<int, char> leadingCharacters; // 0x10
			public Dictionary<int, char> followingCharacters; // 0x18

			// Constructors
			public LineBreakingTable(); // 0x00AC7360-0x00AC7370
		}

		// Constructors
		public TMP_Settings(); // 0x0032F0A0-0x0032F0B0

		// Methods
		public static TMP_Settings LoadDefaultSettings(); // 0x0032E210-0x0032E3F0
		public static TMP_Settings GetSettings(); // 0x0032E3F0-0x0032E710
		public static TMP_FontAsset GetFontAsset(); // 0x0032E710-0x0032EA40
		public static TMP_SpriteAsset GetSpriteAsset(); // 0x0032EA40-0x0032ED70
		public static TMP_StyleSheet GetStyleSheet(); // 0x0032ED70-0x0032F0A0
		public static void LoadLinebreakingRules(); // 0x0032DB60-0x0032DE00
		private static Dictionary<int, char> GetCharacters(TextAsset file); // 0x0032DE00-0x0032DFA0
	}

	public static class ShaderUtilities // TypeDefIndex: 2796
	{
		// Fields
		public static int ID_MainTex; // 0x00
		public static int ID_FaceTex; // 0x04
		public static int ID_FaceColor; // 0x08
		public static int ID_FaceDilate; // 0x0C
		public static int ID_Shininess; // 0x10
		public static int ID_UnderlayColor; // 0x14
		public static int ID_UnderlayOffsetX; // 0x18
		public static int ID_UnderlayOffsetY; // 0x1C
		public static int ID_UnderlayDilate; // 0x20
		public static int ID_UnderlaySoftness; // 0x24
		public static int ID_WeightNormal; // 0x28
		public static int ID_WeightBold; // 0x2C
		public static int ID_OutlineTex; // 0x30
		public static int ID_OutlineWidth; // 0x34
		public static int ID_OutlineSoftness; // 0x38
		public static int ID_OutlineColor; // 0x3C
		public static int ID_Outline2Color; // 0x40
		public static int ID_Outline2Width; // 0x44
		public static int ID_Padding; // 0x48
		public static int ID_GradientScale; // 0x4C
		public static int ID_ScaleX; // 0x50
		public static int ID_ScaleY; // 0x54
		public static int ID_PerspectiveFilter; // 0x58
		public static int ID_Sharpness; // 0x5C
		public static int ID_TextureWidth; // 0x60
		public static int ID_TextureHeight; // 0x64
		public static int ID_BevelAmount; // 0x68
		public static int ID_GlowColor; // 0x6C
		public static int ID_GlowOffset; // 0x70
		public static int ID_GlowPower; // 0x74
		public static int ID_GlowOuter; // 0x78
		public static int ID_GlowInner; // 0x7C
		public static int ID_LightAngle; // 0x80
		public static int ID_EnvMap; // 0x84
		public static int ID_EnvMatrix; // 0x88
		public static int ID_EnvMatrixRotation; // 0x8C
		public static int ID_MaskCoord; // 0x90
		public static int ID_ClipRect; // 0x94
		public static int ID_MaskSoftnessX; // 0x98
		public static int ID_MaskSoftnessY; // 0x9C
		public static int ID_VertexOffsetX; // 0xA0
		public static int ID_VertexOffsetY; // 0xA4
		public static int ID_UseClipRect; // 0xA8
		public static int ID_StencilID; // 0xAC
		public static int ID_StencilOp; // 0xB0
		public static int ID_StencilComp; // 0xB4
		public static int ID_StencilReadMask; // 0xB8
		public static int ID_StencilWriteMask; // 0xBC
		public static int ID_ShaderFlags; // 0xC0
		public static int ID_ScaleRatio_A; // 0xC4
		public static int ID_ScaleRatio_B; // 0xC8
		public static int ID_ScaleRatio_C; // 0xCC
		public static string Keyword_Bevel; // 0xD0
		public static string Keyword_Glow; // 0xD8
		public static string Keyword_Underlay; // 0xE0
		public static string Keyword_Ratios; // 0xE8
		public static string Keyword_MASK_SOFT; // 0xF0
		public static string Keyword_MASK_HARD; // 0xF8
		public static string Keyword_MASK_TEX; // 0x100
		public static string Keyword_Outline; // 0x108
		public static string ShaderTag_ZTestMode; // 0x110
		public static string ShaderTag_CullMode; // 0x118
		private static float m_clamp; // 0x120
		public static bool isInitialized; // 0x124
		private static Shader k_ShaderRef_MobileSDF; // 0x128
		private static Shader k_ShaderRef_MobileBitmap; // 0x130

		// Properties
		internal static Shader ShaderRef_MobileSDF { get; } // 0x0037E6C0-0x0037E8A0
		internal static Shader ShaderRef_MobileBitmap { get; } // 0x0037E8A0-0x0037EA80

		// Constructors
		static ShaderUtilities(); // 0x0037EA80-0x0037EB50

		// Methods
		public static void GetShaderPropertyIDs(); // 0x0037EB50-0x0037FD70
		public static void UpdateShaderRatios(Material mat); // 0x0037FD70-0x00380750
		public static bool IsMaskingEnabled(Material material); // 0x00380750-0x00380A40
		public static float GetPadding(Material material, bool enableExtraPadding, bool isBold); // 0x00380A40-0x00381970
	}

	[Serializable]
	public class TMP_Sprite : TMP_TextElement_Legacy // TypeDefIndex: 2797
	{
		// Fields
		public string name; // 0x38
		public int hashCode; // 0x40
		public int unicode; // 0x44
		public Vector2 pivot; // 0x48
		public Sprite sprite; // 0x50

		// Constructors
		public TMP_Sprite(); // 0x0032F0B0-0x0032F0C0
	}

	[DisallowMultipleComponent] // 0x00253790-0x002537A0
	public class TMP_SpriteAnimator : MonoBehaviour // TypeDefIndex: 2798
	{
		// Fields
		private Dictionary<int, bool> m_animations; // 0x18
		private TMP_Text m_TextComponent; // 0x20

		// Nested types
		private sealed class <DoSpriteAnimationInternal>d__7 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2799
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public TMP_SpriteAnimator <>4__this; // 0x20
			public int start; // 0x28
			public int end; // 0x2C
			public TMP_SpriteAsset spriteAsset; // 0x30
			public int currentCharacter; // 0x38
			public int framerate; // 0x3C
			private int <currentFrame>5__2; // 0x40
			private TMP_CharacterInfo <charInfo>5__3; // 0x48
			private int <materialIndex>5__4; // 0x1B8
			private int <vertexIndex>5__5; // 0x1BC
			private TMP_MeshInfo <meshInfo>5__6; // 0x1C0
			private float <elapsedTime>5__7; // 0x210
			private float <targetTime>5__8; // 0x214

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x002549D0-0x002549E0 */ get; } // 0x00AC7C70-0x00AC7C80
			object IEnumerator.Current { [DebuggerHidden] /* 0x002549E0-0x002549F0 */ get; } // 0x00AC7C80-0x00AC7C90

			// Constructors
			[DebuggerHidden] // 0x002549B0-0x002549C0
			public <DoSpriteAnimationInternal>d__7(int <>1__state); // 0x00AC7370-0x00AC7380

			// Methods
			[DebuggerHidden] // 0x002549C0-0x002549D0
			void IDisposable.Dispose(); // 0x00AC7380-0x00AC7390
			private bool MoveNext(); // 0x00AC7390-0x00AC7C70
		}

		// Constructors
		public TMP_SpriteAnimator(); // 0x0032F330-0x0032F3E0

		// Methods
		private void Awake(); // 0x0032F0C0-0x0032F100
		public void StopAllAnimations(); // 0x0032F100-0x0032F180
		public void DoSpriteAnimation(int currentCharacter, TMP_SpriteAsset spriteAsset, int start, int end, int framerate); // 0x0032F180-0x0032F2B0
		private IEnumerator DoSpriteAnimationInternal(int currentCharacter, TMP_SpriteAsset spriteAsset, int start, int end, int framerate); // 0x0032F2B0-0x0032F330
	}

	public class TMP_SpriteAsset : TMP_Asset // TypeDefIndex: 2800
	{
		// Fields
		internal Dictionary<uint, int> m_UnicodeLookup; // 0x30
		internal Dictionary<int, int> m_NameLookup; // 0x38
		internal Dictionary<uint, int> m_GlyphIndexLookup; // 0x40
		[SerializeField] // 0x002541B0-0x002541C0
		private string m_Version; // 0x48
		[SerializeField] // 0x002541C0-0x002541D0
		internal FaceInfo m_FaceInfo; // 0x50
		public Texture spriteSheet; // 0xA8
		[SerializeField] // 0x002541D0-0x002541E0
		private List<TMP_SpriteCharacter> m_SpriteCharacterTable; // 0xB0
		[SerializeField] // 0x002541E0-0x002541F0
		private List<TMP_SpriteGlyph> m_SpriteGlyphTable; // 0xB8
		public List<TMP_Sprite> spriteInfoList; // 0xC0
		[SerializeField] // 0x002541F0-0x00254200
		public List<TMP_SpriteAsset> fallbackSpriteAssets; // 0xC8
		internal bool m_IsSpriteAssetLookupTablesDirty; // 0xD0
		private static List<int> k_searchedSpriteAssets; // 0x00

		// Properties
		public string version { get; internal set; } // 0x0032F3E0-0x0032F3F0 0x0032F3F0-0x0032F400
		public FaceInfo faceInfo { get; internal set; } // 0x0032F400-0x0032F440 0x0032F440-0x0032F480
		public List<TMP_SpriteCharacter> spriteCharacterTable { get; internal set; } // 0x0032F480-0x0032F4A0 0x0032FEE0-0x0032FEF0
		public List<TMP_SpriteGlyph> spriteGlyphTable { get; internal set; } // 0x0032FEF0-0x0032FF00 0x0032FF00-0x0032FF10

		// Nested types
		[Serializable]
		private sealed class <>c // TypeDefIndex: 2801
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static Func<TMP_SpriteGlyph, uint> <>9__36_0; // 0x08
			public static Func<TMP_SpriteCharacter, uint> <>9__37_0; // 0x10

			// Constructors
			static <>c(); // 0x00AC7C90-0x00AC7CD0
			public <>c(); // 0x00AC7CD0-0x00AC7CE0

			// Methods
			internal uint <SortGlyphTable>b__36_0(TMP_SpriteGlyph item); // 0x00AC7CE0-0x00AC7CF0
			internal uint <SortCharacterTable>b__37_0(TMP_SpriteCharacter c); // 0x00AC7CF0-0x00AC7D10
		}

		// Constructors
		public TMP_SpriteAsset(); // 0x003315A0-0x00331620

		// Methods
		private void Awake(); // 0x0032FF10-0x00330020
		private Material GetDefaultSpriteMaterial(); // 0x00330020-0x00330170
		public void UpdateLookupTables(); // 0x0032F4A0-0x0032F950
		public int GetSpriteIndexFromHashcode(int hashCode); // 0x00330170-0x00330210
		public int GetSpriteIndexFromUnicode(uint unicode); // 0x00330210-0x003302B0
		public int GetSpriteIndexFromName(string name); // 0x003302B0-0x003303A0
		public static TMP_SpriteAsset SearchForSpriteByUnicode(TMP_SpriteAsset spriteAsset, uint unicode, bool includeFallbacks, out int spriteIndex); // 0x003303A0-0x00330710
		private static TMP_SpriteAsset SearchForSpriteByUnicodeInternal(List<TMP_SpriteAsset> spriteAssets, uint unicode, bool includeFallbacks, out int spriteIndex); // 0x00330710-0x003309D0
		private static TMP_SpriteAsset SearchForSpriteByUnicodeInternal(TMP_SpriteAsset spriteAsset, uint unicode, bool includeFallbacks, out int spriteIndex); // 0x003309D0-0x00330AF0
		public static TMP_SpriteAsset SearchForSpriteByHashCode(TMP_SpriteAsset spriteAsset, int hashCode, bool includeFallbacks, out int spriteIndex); // 0x00330AF0-0x00330E60
		private static TMP_SpriteAsset SearchForSpriteByHashCodeInternal(List<TMP_SpriteAsset> spriteAssets, int hashCode, bool searchFallbacks, out int spriteIndex); // 0x00330E60-0x00331120
		private static TMP_SpriteAsset SearchForSpriteByHashCodeInternal(TMP_SpriteAsset spriteAsset, int hashCode, bool searchFallbacks, out int spriteIndex); // 0x00331120-0x00331240
		public void SortGlyphTable(); // 0x00331240-0x00331380
		internal void SortCharacterTable(); // 0x00331380-0x003314C0
		internal void SortGlyphAndCharacterTables(); // 0x003314C0-0x003314E0
		private void UpgradeSpriteAsset(); // 0x0032F950-0x0032FEE0
	}

	[Serializable]
	public class TMP_SpriteCharacter : TMP_TextElement // TypeDefIndex: 2802
	{
		// Fields
		[SerializeField] // 0x00254200-0x00254210
		private string m_Name; // 0x28
		[SerializeField] // 0x00254210-0x00254220
		private int m_HashCode; // 0x30

		// Properties
		public string name { set; } // 0x00331530-0x003315A0
		public int hashCode { get; } // 0x00331620-0x00331630

		// Constructors
		public TMP_SpriteCharacter(); // 0x00331630-0x00331640
		public TMP_SpriteCharacter(uint unicode, TMP_SpriteGlyph glyph); // 0x00331500-0x00331530
	}

	[Serializable]
	public class TMP_SpriteGlyph : Glyph // TypeDefIndex: 2803
	{
		// Fields
		public Sprite sprite; // 0x40

		// Constructors
		public TMP_SpriteGlyph(); // 0x003314E0-0x00331500
	}

	[Serializable]
	public class TMP_Style // TypeDefIndex: 2804
	{
		// Fields
		internal static TMP_Style k_NormalStyle; // 0x00
		[SerializeField] // 0x00254220-0x00254230
		private string m_Name; // 0x10
		[SerializeField] // 0x00254230-0x00254240
		private int m_HashCode; // 0x18
		[SerializeField] // 0x00254240-0x00254250
		private string m_OpeningDefinition; // 0x20
		[SerializeField] // 0x00254250-0x00254260
		private string m_ClosingDefinition; // 0x28
		[SerializeField] // 0x00254260-0x00254270
		private int[] m_OpeningTagArray; // 0x30
		[SerializeField] // 0x00254270-0x00254280
		private int[] m_ClosingTagArray; // 0x38

		// Properties
		public static TMP_Style NormalStyle { get; } // 0x00331640-0x00331720
		public int hashCode { get; } // 0x00331980-0x00331990
		public int[] styleOpeningTagArray { get; } // 0x00331990-0x003319A0
		public int[] styleClosingTagArray { get; } // 0x003319A0-0x003319B0

		// Constructors
		internal TMP_Style(string styleName, string styleOpeningDefinition, string styleClosingDefinition); // 0x00331900-0x00331980

		// Methods
		public void RefreshStyle(); // 0x00331720-0x00331900
	}

	[Serializable]
	public class TMP_StyleSheet : ScriptableObject // TypeDefIndex: 2805
	{
		// Fields
		[SerializeField] // 0x00254280-0x00254290
		private List<TMP_Style> m_StyleList; // 0x18
		private Dictionary<int, TMP_Style> m_StyleLookupDictionary; // 0x20

		// Properties
		internal List<TMP_Style> styles { get; } // 0x003319B0-0x003319C0

		// Constructors
		public TMP_StyleSheet(); // 0x00331CA0-0x00331D30

		// Methods
		public TMP_Style GetStyle(int hashCode); // 0x003319C0-0x00331A60
		public TMP_Style GetStyle(string name); // 0x00331BD0-0x00331C90
		public void RefreshStyles(); // 0x00331C90-0x00331CA0
		private void LoadStyleDictionaryInternal(); // 0x00331A60-0x00331BD0
	}

	[ExecuteAlways] // 0x002537A0-0x00253800
	[RequireComponent] // 0x002537A0-0x00253800
	[RequireComponent] // 0x002537A0-0x00253800
	public class TMP_SubMesh : MonoBehaviour // TypeDefIndex: 2806
	{
		// Fields
		[SerializeField] // 0x00254290-0x002542A0
		private TMP_FontAsset m_fontAsset; // 0x18
		[SerializeField] // 0x002542A0-0x002542B0
		private TMP_SpriteAsset m_spriteAsset; // 0x20
		[SerializeField] // 0x002542B0-0x002542C0
		private Material m_material; // 0x28
		[SerializeField] // 0x002542C0-0x002542D0
		private Material m_sharedMaterial; // 0x30
		private Material m_fallbackMaterial; // 0x38
		private Material m_fallbackSourceMaterial; // 0x40
		[SerializeField] // 0x002542D0-0x002542E0
		private bool m_isDefaultMaterial; // 0x48
		[SerializeField] // 0x002542E0-0x002542F0
		private float m_padding; // 0x4C
		[SerializeField] // 0x002542F0-0x00254300
		private Renderer m_renderer; // 0x50
		[SerializeField] // 0x00254300-0x00254310
		private MeshFilter m_meshFilter; // 0x58
		private Mesh m_mesh; // 0x60
		[SerializeField] // 0x00254310-0x00254320
		private TextMeshPro m_TextComponent; // 0x68
		[NonSerialized]
		private bool m_isRegisteredForEvents; // 0x70

		// Properties
		public TMP_FontAsset fontAsset { get; set; } // 0x00331D30-0x00331D40 0x00331D40-0x00331D50
		public TMP_SpriteAsset spriteAsset { get; set; } // 0x00331D50-0x00331D60 0x00331D60-0x00331D70
		public Material material { get; set; } // 0x00331D70-0x00331D80 0x00332760-0x00332820
		public Material sharedMaterial { get; set; } // 0x003328A0-0x003328B0 0x003328B0-0x003328C0
		public Material fallbackMaterial { get; set; } // 0x00332940-0x00332950 0x00332950-0x00332B80
		public Material fallbackSourceMaterial { get; set; } // 0x00332B80-0x00332B90 0x00332B90-0x00332BA0
		public bool isDefaultMaterial { get; set; } // 0x00332BA0-0x00332BB0 0x00332BB0-0x00332BC0
		public float padding { get; set; } // 0x00332BC0-0x00332BD0 0x00332BD0-0x00332BE0
		public Renderer renderer { get; } // 0x00332BE0-0x00332CE0
		public MeshFilter meshFilter { get; } // 0x00332CE0-0x00332DE0
		public Mesh mesh { get; set; } // 0x00332DE0-0x00333080 0x00333080-0x00333090
		public TMP_Text textComponent { get; } // 0x00333090-0x00333190

		// Constructors
		public TMP_SubMesh(); // 0x00334440-0x00334480

		// Methods
		private void OnEnable(); // 0x00333190-0x00333460
		private void OnDisable(); // 0x00333460-0x003335D0
		private void OnDestroy(); // 0x003335D0-0x00333820
		public static TMP_SubMesh AddSubTextObject(TextMeshPro textComponent, MaterialReference materialReference); // 0x00333860-0x003341D0
		public void DestroySelf(); // 0x003341D0-0x00334290
		private Material GetMaterial(Material mat); // 0x00331D80-0x00332000
		private Material CreateMaterialInstance(Material source); // 0x00332000-0x00332100
		private Material GetSharedMaterial(); // 0x00334290-0x003343E0
		private void SetSharedMaterial(Material mat); // 0x003328C0-0x00332940
		public float GetPaddingForMaterial(); // 0x00332820-0x00332890
		public void UpdateMeshPadding(bool isExtraPadding, bool isUsingBold); // 0x003343E0-0x00334440
		public void SetVerticesDirty(); // 0x00332100-0x00332290
		public void SetMaterialDirty(); // 0x00332890-0x003328A0
		protected void UpdateMaterial(); // 0x00332290-0x00332760
	}

	[ExecuteAlways] // 0x00253800-0x00253840
	[RequireComponent] // 0x00253800-0x00253840
	public class TMP_SubMeshUI : MaskableGraphic, IClippable, IMaskable, IMaterialModifier // TypeDefIndex: 2807
	{
		// Fields
		[SerializeField] // 0x00254320-0x00254330
		private TMP_FontAsset m_fontAsset; // 0xD0
		[SerializeField] // 0x00254330-0x00254340
		private TMP_SpriteAsset m_spriteAsset; // 0xD8
		[SerializeField] // 0x00254340-0x00254350
		private Material m_material; // 0xE0
		[SerializeField] // 0x00254350-0x00254360
		private Material m_sharedMaterial; // 0xE8
		private Material m_fallbackMaterial; // 0xF0
		private Material m_fallbackSourceMaterial; // 0xF8
		[SerializeField] // 0x00254360-0x00254370
		private bool m_isDefaultMaterial; // 0x100
		[SerializeField] // 0x00254370-0x00254380
		private float m_padding; // 0x104
		private Mesh m_mesh; // 0x108
		[SerializeField] // 0x00254380-0x00254390
		private TextMeshProUGUI m_TextComponent; // 0x110
		[NonSerialized]
		private bool m_isRegisteredForEvents; // 0x118
		private bool m_materialDirty; // 0x119
		[SerializeField] // 0x00254390-0x002543A0
		private int m_materialReferenceIndex; // 0x11C

		// Properties
		public TMP_FontAsset fontAsset { get; set; } // 0x00334480-0x00334490 0x00334490-0x003344A0
		public TMP_SpriteAsset spriteAsset { get; set; } // 0x003344A0-0x003344B0 0x003344B0-0x003344C0
		public override Texture mainTexture { get; } // 0x003344C0-0x00334640
		public override Material material { get; set; } // 0x00334640-0x00334650 0x00334930-0x00334AF0
		public Material sharedMaterial { get; set; } // 0x00334B70-0x00334B80 0x00334B80-0x00334B90
		public Material fallbackMaterial { get; set; } // 0x00334C30-0x00334C40 0x00334C40-0x00334E80
		public Material fallbackSourceMaterial { get; set; } // 0x00334E80-0x00334E90 0x00334E90-0x00334EA0
		public override Material materialForRendering { get; } // 0x00334EA0-0x00334F00
		public bool isDefaultMaterial { get; set; } // 0x00334F00-0x00334F10 0x00334F10-0x00334F20
		public float padding { get; set; } // 0x00334F20-0x00334F30 0x00334F30-0x00334F40
		public Mesh mesh { get; set; } // 0x00334F40-0x003350A0 0x003350A0-0x003350B0
		public TMP_Text textComponent { get; } // 0x003350B0-0x003351C0

		// Constructors
		public TMP_SubMeshUI(); // 0x00337110-0x00337120

		// Methods
		public static TMP_SubMeshUI AddSubTextObject(TextMeshProUGUI textComponent, MaterialReference materialReference); // 0x003351C0-0x00335A20
		protected override void OnEnable(); // 0x00335C40-0x00335C90
		protected override void OnDisable(); // 0x00335C90-0x00335EB0
		protected override void OnDestroy(); // 0x00335EB0-0x00336220
		protected override void OnTransformParentChanged(); // 0x00336220-0x00336270
		public override Material GetModifiedMaterial(Material baseMaterial); // 0x00336270-0x00336560
		public float GetPaddingForMaterial(); // 0x00334AF0-0x00334B70
		public float GetPaddingForMaterial(Material mat); // 0x00336560-0x003365D0
		public void UpdateMeshPadding(bool isExtraPadding, bool isUsingBold); // 0x003365D0-0x00336640
		public override void SetAllDirty(); // 0x00336640-0x00336650
		public override void SetVerticesDirty(); // 0x00336650-0x003367C0
		public override void SetLayoutDirty(); // 0x003367C0-0x003367D0
		public override void SetMaterialDirty(); // 0x003367D0-0x00336800
		public void SetPivotDirty(); // 0x00336800-0x00336A20
		public override void Cull(Rect clipRect, bool validRect); // 0x00336A20-0x00336C70
		protected override void UpdateGeometry(); // 0x00336C70-0x00336C80
		public override void Rebuild(CanvasUpdate update); // 0x00336C80-0x00336CB0
		public void RefreshMaterial(); // 0x00336CB0-0x00336CD0
		protected override void UpdateMaterial(); // 0x00336CD0-0x00337070
		public override void RecalculateClipping(); // 0x00337070-0x00337080
		public override void RecalculateMasking(); // 0x00337080-0x003370A0
		private Material GetMaterial(); // 0x003370A0-0x003370B0
		private Material GetMaterial(Material mat); // 0x00334650-0x00334830
		private Material CreateMaterialInstance(Material source); // 0x00334830-0x00334930
		private Material GetSharedMaterial(); // 0x003370B0-0x00337110
		private void SetSharedMaterial(Material mat); // 0x00334B90-0x00334C30
	}

	public enum TextAlignmentOptions // TypeDefIndex: 2808
	{
		TopLeft = 257,
		Top = 258,
		TopRight = 260,
		TopJustified = 264,
		TopFlush = 272,
		TopGeoAligned = 288,
		Left = 513,
		Center = 514,
		Right = 516,
		Justified = 520,
		Flush = 528,
		CenterGeoAligned = 544,
		BottomLeft = 1025,
		Bottom = 1026,
		BottomRight = 1028,
		BottomJustified = 1032,
		BottomFlush = 1040,
		BottomGeoAligned = 1056,
		BaselineLeft = 2049,
		Baseline = 2050,
		BaselineRight = 2052,
		BaselineJustified = 2056,
		BaselineFlush = 2064,
		BaselineGeoAligned = 2080,
		MidlineLeft = 4097,
		Midline = 4098,
		MidlineRight = 4100,
		MidlineJustified = 4104,
		MidlineFlush = 4112,
		MidlineGeoAligned = 4128,
		CaplineLeft = 8193,
		Capline = 8194,
		CaplineRight = 8196,
		CaplineJustified = 8200,
		CaplineFlush = 8208,
		CaplineGeoAligned = 8224,
		Converted = 65535
	}

	public enum HorizontalAlignmentOptions // TypeDefIndex: 2809
	{
		Left = 1,
		Center = 2,
		Right = 4,
		Justified = 8,
		Flush = 16,
		Geometry = 32
	}

	public enum VerticalAlignmentOptions // TypeDefIndex: 2810
	{
		Top = 256,
		Middle = 512,
		Bottom = 1024,
		Baseline = 2048,
		Geometry = 4096,
		Capline = 8192
	}

	public enum TextRenderFlags // TypeDefIndex: 2811
	{
		DontRender = 0,
		Render = 255
	}

	public enum TMP_TextElementType // TypeDefIndex: 2812
	{
		Character = 0,
		Sprite = 1
	}

	public enum MaskingTypes // TypeDefIndex: 2813
	{
		MaskOff = 0,
		MaskHard = 1,
		MaskSoft = 2
	}

	public enum TextOverflowModes // TypeDefIndex: 2814
	{
		Overflow = 0,
		Ellipsis = 1,
		Masking = 2,
		Truncate = 3,
		ScrollRect = 4,
		Page = 5,
		Linked = 6
	}

	public enum TextureMappingOptions // TypeDefIndex: 2815
	{
		Character = 0,
		Line = 1,
		Paragraph = 2,
		MatchAspect = 3
	}

	[Flags] // 0x00253840-0x00253850
	public enum FontStyles // TypeDefIndex: 2816
	{
		Normal = 0,
		Bold = 1,
		Italic = 2,
		Underline = 4,
		LowerCase = 8,
		UpperCase = 16,
		SmallCaps = 32,
		Strikethrough = 64,
		Superscript = 128,
		Subscript = 256,
		Highlight = 512
	}

	public enum FontWeight // TypeDefIndex: 2817
	{
		Thin = 100,
		ExtraLight = 200,
		Light = 300,
		Regular = 400,
		Medium = 500,
		SemiBold = 600,
		Bold = 700,
		Heavy = 800,
		Black = 900
	}

	public abstract class TMP_Text : MaskableGraphic // TypeDefIndex: 2818
	{
		// Fields
		[SerializeField] // 0x002543A0-0x002543B0
		protected string m_text; // 0xD0
		[SerializeField] // 0x002543B0-0x002543C0
		protected ITextPreprocessor m_TextPreprocessor; // 0xD8
		[SerializeField] // 0x002543C0-0x002543D0
		protected bool m_isRightToLeft; // 0xE0
		[SerializeField] // 0x002543D0-0x002543E0
		protected TMP_FontAsset m_fontAsset; // 0xE8
		protected TMP_FontAsset m_currentFontAsset; // 0xF0
		protected bool m_isSDFShader; // 0xF8
		[SerializeField] // 0x002543E0-0x002543F0
		protected Material m_sharedMaterial; // 0x100
		protected Material m_currentMaterial; // 0x108
		protected MaterialReference[] m_materialReferences; // 0x110
		protected Dictionary<int, int> m_materialReferenceIndexLookup; // 0x118
		protected TMP_RichTextTagStack<MaterialReference> m_materialReferenceStack; // 0x120
		protected int m_currentMaterialIndex; // 0x168
		[SerializeField] // 0x002543F0-0x00254400
		protected Material[] m_fontSharedMaterials; // 0x170
		[SerializeField] // 0x00254400-0x00254410
		protected Material m_fontMaterial; // 0x178
		[SerializeField] // 0x00254410-0x00254420
		protected Material[] m_fontMaterials; // 0x180
		protected bool m_isMaterialDirty; // 0x188
		[SerializeField] // 0x00254420-0x00254430
		protected Color32 m_fontColor32; // 0x18C
		[SerializeField] // 0x00254430-0x00254440
		protected Color m_fontColor; // 0x190
		protected static Color32 s_colorWhite; // 0x00
		protected Color32 m_underlineColor; // 0x1A0
		protected Color32 m_strikethroughColor; // 0x1A4
		[SerializeField] // 0x00254440-0x00254450
		protected bool m_enableVertexGradient; // 0x1A8
		[SerializeField] // 0x00254450-0x00254460
		protected ColorMode m_colorMode; // 0x1AC
		[SerializeField] // 0x00254460-0x00254470
		protected VertexGradient m_fontColorGradient; // 0x1B0
		[SerializeField] // 0x00254470-0x00254480
		protected TMP_ColorGradient m_fontColorGradientPreset; // 0x1F0
		[SerializeField] // 0x00254480-0x00254490
		protected TMP_SpriteAsset m_spriteAsset; // 0x1F8
		[SerializeField] // 0x00254490-0x002544A0
		protected bool m_tintAllSprites; // 0x200
		protected bool m_tintSprite; // 0x201
		protected Color32 m_spriteColor; // 0x204
		[SerializeField] // 0x002544A0-0x002544B0
		protected TMP_StyleSheet m_StyleSheet; // 0x208
		internal TMP_Style m_TextStyle; // 0x210
		[SerializeField] // 0x002544B0-0x002544C0
		protected int m_TextStyleHashCode; // 0x218
		[SerializeField] // 0x002544C0-0x002544D0
		protected bool m_overrideHtmlColors; // 0x21C
		[SerializeField] // 0x002544D0-0x002544E0
		protected Color32 m_faceColor; // 0x220
		[SerializeField] // 0x002544E0-0x002544F0
		protected Color32 m_outlineColor; // 0x224
		protected float m_outlineWidth; // 0x228
		[SerializeField] // 0x002544F0-0x00254500
		protected float m_fontSize; // 0x22C
		protected float m_currentFontSize; // 0x230
		[SerializeField] // 0x00254500-0x00254510
		protected float m_fontSizeBase; // 0x234
		protected TMP_RichTextTagStack<float> m_sizeStack; // 0x238
		[SerializeField] // 0x00254510-0x00254520
		protected FontWeight m_fontWeight; // 0x250
		protected FontWeight m_FontWeightInternal; // 0x254
		protected TMP_RichTextTagStack<FontWeight> m_FontWeightStack; // 0x258
		[SerializeField] // 0x00254520-0x00254530
		protected bool m_enableAutoSizing; // 0x270
		protected float m_maxFontSize; // 0x274
		protected float m_minFontSize; // 0x278
		protected int m_AutoSizeIterationCount; // 0x27C
		protected int m_AutoSizeMaxIterationCount; // 0x280
		protected bool m_IsAutoSizePointSizeSet; // 0x284
		[SerializeField] // 0x00254530-0x00254540
		protected float m_fontSizeMin; // 0x288
		[SerializeField] // 0x00254540-0x00254550
		protected float m_fontSizeMax; // 0x28C
		[SerializeField] // 0x00254550-0x00254560
		protected FontStyles m_fontStyle; // 0x290
		protected FontStyles m_FontStyleInternal; // 0x294
		protected TMP_FontStyleStack m_fontStyleStack; // 0x298
		protected bool m_isUsingBold; // 0x2A2
		[SerializeField] // 0x00254560-0x00254570
		protected HorizontalAlignmentOptions m_HorizontalAlignment; // 0x2A4
		[SerializeField] // 0x00254570-0x00254580
		protected VerticalAlignmentOptions m_VerticalAlignment; // 0x2A8
		[FormerlySerializedAs] // 0x00254580-0x002545A0
		[SerializeField] // 0x00254580-0x002545A0
		protected TextAlignmentOptions m_textAlignment; // 0x2AC
		protected HorizontalAlignmentOptions m_lineJustification; // 0x2B0
		protected TMP_RichTextTagStack<HorizontalAlignmentOptions> m_lineJustificationStack; // 0x2B8
		protected Vector3[] m_textContainerLocalCorners; // 0x2D0
		[SerializeField] // 0x002545A0-0x002545B0
		protected float m_characterSpacing; // 0x2D8
		protected float m_cSpacing; // 0x2DC
		protected float m_monoSpacing; // 0x2E0
		[SerializeField] // 0x002545B0-0x002545C0
		protected float m_wordSpacing; // 0x2E4
		[SerializeField] // 0x002545C0-0x002545D0
		protected float m_lineSpacing; // 0x2E8
		protected float m_lineSpacingDelta; // 0x2EC
		protected float m_lineHeight; // 0x2F0
		protected bool m_IsDrivenLineSpacing; // 0x2F4
		[SerializeField] // 0x002545D0-0x002545E0
		protected float m_lineSpacingMax; // 0x2F8
		[SerializeField] // 0x002545E0-0x002545F0
		protected float m_paragraphSpacing; // 0x2FC
		[SerializeField] // 0x002545F0-0x00254600
		protected float m_charWidthMaxAdj; // 0x300
		protected float m_charWidthAdjDelta; // 0x304
		[SerializeField] // 0x00254600-0x00254610
		protected bool m_enableWordWrapping; // 0x308
		protected bool m_isCharacterWrappingEnabled; // 0x309
		protected bool m_isNonBreakingSpace; // 0x30A
		protected bool m_isIgnoringAlignment; // 0x30B
		[SerializeField] // 0x00254610-0x00254620
		protected float m_wordWrappingRatios; // 0x30C
		[SerializeField] // 0x00254620-0x00254630
		protected TextOverflowModes m_overflowMode; // 0x310
		[SerializeField] // 0x00254630-0x00254640
		protected int m_firstOverflowCharacterIndex; // 0x314
		[SerializeField] // 0x00254640-0x00254650
		protected TMP_Text m_linkedTextComponent; // 0x318
		[SerializeField] // 0x00254650-0x00254660
		internal TMP_Text parentLinkedComponent; // 0x320
		[SerializeField] // 0x00254660-0x00254670
		protected bool m_isTextTruncated; // 0x328
		[SerializeField] // 0x00254670-0x00254680
		protected bool m_enableKerning; // 0x329
		[SerializeField] // 0x00254680-0x00254690
		protected bool m_enableExtraPadding; // 0x32A
		[SerializeField] // 0x00254690-0x002546A0
		protected bool checkPaddingRequired; // 0x32B
		[SerializeField] // 0x002546A0-0x002546B0
		protected bool m_isRichText; // 0x32C
		[SerializeField] // 0x002546B0-0x002546C0
		protected bool m_parseCtrlCharacters; // 0x32D
		protected bool m_isOverlay; // 0x32E
		[SerializeField] // 0x002546C0-0x002546D0
		protected bool m_isOrthographic; // 0x32F
		[SerializeField] // 0x002546D0-0x002546E0
		protected bool m_isCullingEnabled; // 0x330
		protected bool m_isMaskingEnabled; // 0x331
		protected bool isMaskUpdateRequired; // 0x332
		[SerializeField] // 0x002546E0-0x002546F0
		protected bool m_ignoreCulling; // 0x333
		[SerializeField] // 0x002546F0-0x00254700
		protected TextureMappingOptions m_horizontalMapping; // 0x334
		[SerializeField] // 0x00254700-0x00254710
		protected TextureMappingOptions m_verticalMapping; // 0x338
		[SerializeField] // 0x00254710-0x00254720
		protected float m_uvLineOffset; // 0x33C
		protected TextRenderFlags m_renderMode; // 0x340
		[SerializeField] // 0x00254720-0x00254730
		protected VertexSortingOrder m_geometrySortingOrder; // 0x344
		[SerializeField] // 0x00254730-0x00254740
		protected bool m_IsTextObjectScaleStatic; // 0x348
		[SerializeField] // 0x00254740-0x00254750
		protected bool m_VertexBufferAutoSizeReduction; // 0x349
		[SerializeField] // 0x00254750-0x00254760
		protected int m_firstVisibleCharacter; // 0x34C
		protected int m_maxVisibleCharacters; // 0x350
		protected int m_maxVisibleWords; // 0x354
		protected int m_maxVisibleLines; // 0x358
		[SerializeField] // 0x00254760-0x00254770
		protected bool m_useMaxVisibleDescender; // 0x35C
		[SerializeField] // 0x00254770-0x00254780
		protected int m_pageToDisplay; // 0x360
		protected bool m_isNewPage; // 0x364
		[SerializeField] // 0x00254780-0x00254790
		protected Vector4 m_margin; // 0x368
		protected float m_marginLeft; // 0x378
		protected float m_marginRight; // 0x37C
		protected float m_marginWidth; // 0x380
		protected float m_marginHeight; // 0x384
		protected float m_width; // 0x388
		[SerializeField] // 0x00254790-0x002547A0
		protected TMP_TextInfo m_textInfo; // 0x390
		protected bool m_havePropertiesChanged; // 0x398
		[SerializeField] // 0x002547A0-0x002547B0
		protected bool m_isUsingLegacyAnimationComponent; // 0x399
		protected Transform m_transform; // 0x3A0
		protected RectTransform m_rectTransform; // 0x3A8
		protected Rect m_RectTransformRect; // 0x3B0
		private bool <autoSizeTextContainer>k__BackingField; // 0x3C0
		protected bool m_autoSizeTextContainer; // 0x3C1
		protected Mesh m_mesh; // 0x3C8
		[SerializeField] // 0x002547B0-0x002547C0
		protected bool m_isVolumetricText; // 0x3D0
		private static Func<int, string, TMP_FontAsset> onFontAssetRequest; // 0x08
		private static Func<int, string, TMP_SpriteAsset> onSpriteAssetRequest; // 0x10
		[SerializeField] // 0x002547C0-0x002547D0
		protected TMP_SpriteAnimator m_spriteAnimator; // 0x3D8
		protected float m_flexibleHeight; // 0x3E0
		protected float m_flexibleWidth; // 0x3E4
		protected float m_minWidth; // 0x3E8
		protected float m_minHeight; // 0x3EC
		protected float m_maxWidth; // 0x3F0
		protected float m_maxHeight; // 0x3F4
		protected LayoutElement m_LayoutElement; // 0x3F8
		protected float m_preferredWidth; // 0x400
		protected float m_renderedWidth; // 0x404
		protected bool m_isPreferredWidthDirty; // 0x408
		protected float m_preferredHeight; // 0x40C
		protected float m_renderedHeight; // 0x410
		protected bool m_isPreferredHeightDirty; // 0x414
		protected bool m_isCalculatingPreferredValues; // 0x415
		protected int m_layoutPriority; // 0x418
		protected bool m_isCalculateSizeRequired; // 0x41C
		protected bool m_isLayoutDirty; // 0x41D
		protected bool m_isAwake; // 0x41E
		internal bool m_isWaitingOnResourceLoad; // 0x41F
		internal bool m_isInputParsingRequired; // 0x420
		internal TextInputSources m_inputSource; // 0x424
		protected float m_fontScale; // 0x428
		protected float m_fontScaleMultiplier; // 0x42C
		protected char[] m_htmlTag; // 0x430
		protected RichTextTagAttribute[] m_xmlAttribute; // 0x438
		protected float[] m_attributeParameterValues; // 0x440
		protected float tag_LineIndent; // 0x448
		protected float tag_Indent; // 0x44C
		protected TMP_RichTextTagStack<float> m_indentStack; // 0x450
		protected bool tag_NoParsing; // 0x468
		protected bool m_isParsingText; // 0x469
		protected Matrix4x4 m_FXMatrix; // 0x46C
		protected bool m_isFXMatrixSet; // 0x4AC
		protected UnicodeChar[] m_InternalParsingBuffer; // 0x4B0
		protected int m_InternalParsingBufferSize; // 0x4B8
		private TMP_CharacterInfo[] m_internalCharacterInfo; // 0x4C0
		protected char[] m_input_CharArray; // 0x4C8
		private int m_charArray_Length; // 0x4D0
		protected int m_totalCharacterCount; // 0x4D4
		protected WordWrapState m_SavedWordWrapState; // 0x4D8
		protected WordWrapState m_SavedLineState; // 0x7C8
		protected WordWrapState m_SavedEllipsisState; // 0xAB8
		protected WordWrapState m_SavedLastValidState; // 0xDA8
		protected WordWrapState m_SavedSoftLineBreakState; // 0x1098
		protected int m_characterCount; // 0x1388
		protected int m_firstCharacterOfLine; // 0x138C
		protected int m_firstVisibleCharacterOfLine; // 0x1390
		protected int m_lastCharacterOfLine; // 0x1394
		protected int m_lastVisibleCharacterOfLine; // 0x1398
		protected int m_lineNumber; // 0x139C
		protected int m_lineVisibleCharacterCount; // 0x13A0
		protected int m_pageNumber; // 0x13A4
		protected float m_PageAscender; // 0x13A8
		protected float m_maxAscender; // 0x13AC
		protected float m_maxCapHeight; // 0x13B0
		protected float m_ElementAscender; // 0x13B4
		protected float m_ElementDescender; // 0x13B8
		protected float m_maxLineAscender; // 0x13BC
		protected float m_maxLineDescender; // 0x13C0
		protected float m_startOfLineAscender; // 0x13C4
		protected float m_lineOffset; // 0x13C8
		protected Extents m_meshExtents; // 0x13CC
		protected Color32 m_htmlColor; // 0x13DC
		protected TMP_RichTextTagStack<Color32> m_colorStack; // 0x13E0
		protected TMP_RichTextTagStack<Color32> m_underlineColorStack; // 0x13F8
		protected TMP_RichTextTagStack<Color32> m_strikethroughColorStack; // 0x1410
		protected TMP_RichTextTagStack<HighlightState> m_HighlightStateStack; // 0x1428
		protected TMP_ColorGradient m_colorGradientPreset; // 0x1450
		protected TMP_RichTextTagStack<TMP_ColorGradient> m_colorGradientStack; // 0x1458
		protected bool m_colorGradientPresetIsTinted; // 0x1470
		protected float m_tabSpacing; // 0x1474
		protected float m_spacing; // 0x1478
		protected TMP_RichTextTagStack<int>[] m_TextStyleStacks; // 0x1480
		protected int m_TextStyleStackDepth; // 0x1488
		protected TMP_RichTextTagStack<int> m_ItalicAngleStack; // 0x1490
		protected int m_ItalicAngle; // 0x14A8
		protected TMP_RichTextTagStack<int> m_actionStack; // 0x14B0
		protected float m_padding; // 0x14C8
		protected float m_baselineOffset; // 0x14CC
		protected TMP_RichTextTagStack<float> m_baselineOffsetStack; // 0x14D0
		protected float m_xAdvance; // 0x14E8
		protected TMP_TextElementType m_textElementType; // 0x14EC
		protected TMP_TextElement m_cached_TextElement; // 0x14F0
		protected SpecialCharacter m_Ellipsis; // 0x14F8
		protected SpecialCharacter m_Underline; // 0x1518
		protected TMP_SpriteAsset m_defaultSpriteAsset; // 0x1538
		protected TMP_SpriteAsset m_currentSpriteAsset; // 0x1540
		protected int m_spriteCount; // 0x1548
		protected int m_spriteIndex; // 0x154C
		protected int m_spriteAnimationID; // 0x1550
		internal bool ignoreClipping; // 0x1554
		protected bool m_ignoreActiveState; // 0x1555
		private readonly decimal[] k_Power; // 0x1558
		protected static Vector2 k_LargePositiveVector2; // 0x18
		protected static Vector2 k_LargeNegativeVector2; // 0x20
		protected static float k_LargePositiveFloat; // 0x28
		protected static float k_LargeNegativeFloat; // 0x2C
		protected static int k_LargePositiveInt; // 0x30
		protected static int k_LargeNegativeInt; // 0x34

		// Properties
		public virtual string text { get; set; } // 0x00337120-0x00337130 0x00337130-0x00337210
		public ITextPreprocessor textPreprocessor { get; set; } // 0x00337210-0x00337220 0x00337220-0x00337230
		public bool isRightToLeftText { get; set; } // 0x00337230-0x00337240 0x00337240-0x003372A0
		public TMP_FontAsset font { get; set; } // 0x003372A0-0x003372B0 0x003372B0-0x003373B0
		public virtual Material fontSharedMaterial { get; set; } // 0x003373B0-0x003373C0 0x003373C0-0x003374B0
		public virtual Material[] fontSharedMaterials { get; set; } // 0x003374B0-0x003374D0 0x003374D0-0x00337520
		public Material fontMaterial { get; set; } // 0x00337520-0x00337540 0x00337540-0x003376B0
		public virtual Material[] fontMaterials { get; set; } // 0x003376B0-0x003376D0 0x003376D0-0x00337720
		public override Color color { get; set; } // 0x00337720-0x00337740 0x00337740-0x00337840
		public float alpha { get; set; } // 0x00337840-0x00337850 0x00337850-0x00337890
		public bool enableVertexGradient { get; set; } // 0x00337890-0x003378A0 0x003378A0-0x003378E0
		public VertexGradient colorGradient { get; set; } // 0x003378E0-0x00337910 0x00337910-0x00337960
		public TMP_ColorGradient colorGradientPreset { get; set; } // 0x00337960-0x00337970 0x00337970-0x003379A0
		public TMP_SpriteAsset spriteAsset { get; set; } // 0x003379A0-0x003379B0 0x003379B0-0x00337A00
		public bool tintAllSprites { get; set; } // 0x00337A00-0x00337A10 0x00337A10-0x00337A50
		public TMP_StyleSheet styleSheet { get; set; } // 0x00337A50-0x00337A60 0x00337A60-0x00337AB0
		public TMP_Style textStyle { get; set; } // 0x00337AB0-0x00337AF0 0x00337DD0-0x00337E30
		public bool overrideColorTags { get; set; } // 0x00337E30-0x00337E40 0x00337E40-0x00337E80
		public Color32 faceColor { get; set; } // 0x00337E80-0x00338020 0x00338020-0x003380C0
		public Color32 outlineColor { get; set; } // 0x003380C0-0x00338260 0x00338260-0x003382E0
		public float outlineWidth { get; set; } // 0x003382E0-0x00338460 0x00338460-0x003384D0
		public float fontSize { get; set; } // 0x003384D0-0x003384E0 0x003384E0-0x00338550
		public float fontScale { get; } // 0x00338550-0x00338560
		public FontWeight fontWeight { get; set; } // 0x00338560-0x00338570 0x00338570-0x003385D0
		public float pixelsPerUnit { get; } // 0x003385D0-0x003387E0
		public bool enableAutoSizing { get; set; } // 0x003387E0-0x003387F0 0x003387F0-0x00338840
		public float fontSizeMin { get; set; } // 0x00338840-0x00338850 0x00338850-0x003388A0
		public float fontSizeMax { get; set; } // 0x003388A0-0x003388B0 0x003388B0-0x00338900
		public FontStyles fontStyle { get; set; } // 0x00338900-0x00338910 0x00338910-0x00338970
		public bool isUsingBold { get; } // 0x00338970-0x00338980
		public HorizontalAlignmentOptions horizontalAlignment { get; set; } // 0x00338980-0x00338990 0x00338990-0x003389C0
		public VerticalAlignmentOptions verticalAlignment { get; set; } // 0x003389C0-0x003389D0 0x003389D0-0x00338A00
		public TextAlignmentOptions alignment { get; set; } // 0x00338A00-0x00338A10 0x00338A10-0x00338A60
		public float characterSpacing { get; set; } // 0x00338A60-0x00338A70 0x00338A70-0x00338AD0
		public float wordSpacing { get; set; } // 0x00338AD0-0x00338AE0 0x00338AE0-0x00338B40
		public float lineSpacing { get; set; } // 0x00338B40-0x00338B50 0x00338B50-0x00338BB0
		public float lineSpacingAdjustment { get; set; } // 0x00338BB0-0x00338BC0 0x00338BC0-0x00338C20
		public float paragraphSpacing { get; set; } // 0x00338C20-0x00338C30 0x00338C30-0x00338C90
		public float characterWidthAdjustment { get; set; } // 0x00338C90-0x00338CA0 0x00338CA0-0x00338D00
		public bool enableWordWrapping { get; set; } // 0x00338D00-0x00338D10 0x00338D10-0x00338D70
		public float wordWrappingRatios { get; set; } // 0x00338D70-0x00338D80 0x00338D80-0x00338DE0
		public TextOverflowModes overflowMode { get; set; } // 0x00338DE0-0x00338DF0 0x00338DF0-0x00338E40
		public bool isTextOverflowing { get; } // 0x00338E40-0x00338E50
		public int firstOverflowCharacterIndex { get; } // 0x00338E50-0x00338E60
		public TMP_Text linkedTextComponent { get; set; } // 0x00338E60-0x00338E70 0x00338E70-0x00338FE0
		public bool isTextTruncated { get; } // 0x003393E0-0x003393F0
		public bool enableKerning { get; set; } // 0x003393F0-0x00339400 0x00339400-0x00339460
		public bool extraPadding { get; set; } // 0x00339460-0x00339470 0x00339470-0x003394C0
		public bool richText { get; set; } // 0x003394C0-0x003394D0 0x003394D0-0x00339530
		public bool parseCtrlCharacters { get; set; } // 0x00339530-0x00339540 0x00339540-0x003395A0
		public bool isOverlay { get; set; } // 0x003395A0-0x003395B0 0x003395B0-0x00339600
		public bool isOrthographic { get; set; } // 0x00339600-0x00339610 0x00339610-0x00339650
		public bool enableCulling { get; set; } // 0x00339650-0x00339660 0x00339660-0x003396A0
		public bool ignoreVisibility { get; set; } // 0x003396A0-0x003396B0 0x003396B0-0x003396D0
		public TextureMappingOptions horizontalMapping { get; set; } // 0x003396D0-0x003396E0 0x003396E0-0x00339710
		public TextureMappingOptions verticalMapping { get; set; } // 0x00339710-0x00339720 0x00339720-0x00339750
		public float mappingUvLineOffset { get; set; } // 0x00339750-0x00339760 0x00339760-0x003397A0
		public TextRenderFlags renderMode { get; set; } // 0x003397A0-0x003397B0 0x003397B0-0x003397D0
		public VertexSortingOrder geometrySortingOrder { get; set; } // 0x003397D0-0x003397E0 0x003397E0-0x00339800
		public bool isTextObjectScaleStatic { get; set; } // 0x00339800-0x00339810 0x00339810-0x00339830
		public bool vertexBufferAutoSizeReduction { get; set; } // 0x00339830-0x00339840 0x00339840-0x00339870
		public int firstVisibleCharacter { get; set; } // 0x00339870-0x00339880 0x00339880-0x003398B0
		public int maxVisibleCharacters { get; set; } // 0x003398B0-0x003398C0 0x003398C0-0x003398F0
		public int maxVisibleWords { get; set; } // 0x003398F0-0x00339900 0x00339900-0x00339930
		public int maxVisibleLines { get; set; } // 0x00339930-0x00339940 0x00339940-0x00339970
		public bool useMaxVisibleDescender { get; set; } // 0x00339970-0x00339980 0x00339980-0x003399C0
		public int pageToDisplay { get; set; } // 0x003399C0-0x003399D0 0x003399D0-0x00339A00
		public virtual Vector4 margin { get; set; } // 0x00339A00-0x00339A20 0x00339A20-0x00339B20
		public TMP_TextInfo textInfo { get; } // 0x00339B20-0x00339B30
		public bool havePropertiesChanged { get; set; } // 0x00339B30-0x00339B40 0x00333820-0x00333860
		public bool isUsingLegacyAnimationComponent { get; set; } // 0x00339B40-0x00339B50 0x00339B50-0x00339B60
		public new Transform transform { get; } // 0x00335A20-0x00335B30
		public new RectTransform rectTransform { get; } // 0x00335B30-0x00335C40
		public virtual bool autoSizeTextContainer { get; set; } // 0x00339B60-0x00339B70 0x00339B70-0x00339B80
		public virtual Mesh mesh { get; } // 0x00339B80-0x00339B90
		public bool isVolumetricText { get; set; } // 0x00339B90-0x00339BA0 0x00339BA0-0x00339C80
		public Bounds bounds { get; } // 0x00339C80-0x00339DA0
		public Bounds textBounds { get; } // 0x00339DA0-0x00339DD0
		protected TMP_SpriteAnimator spriteAnimator { get; } // 0x0033A450-0x0033A680
		public float flexibleHeight { get; } // 0x0033A680-0x0033A690
		public float flexibleWidth { get; } // 0x0033A690-0x0033A6A0
		public float minWidth { get; } // 0x0033A6A0-0x0033A6B0
		public float minHeight { get; } // 0x0033A6B0-0x0033A6C0
		public float maxWidth { get; } // 0x0033A6C0-0x0033A6D0
		public float maxHeight { get; } // 0x0033A6D0-0x0033A6E0
		protected LayoutElement layoutElement { get; } // 0x0033A6E0-0x0033A7F0
		public virtual float preferredWidth { get; } // 0x0033A7F0-0x0033A820
		public virtual float preferredHeight { get; } // 0x0033EEC0-0x0033EEF0
		public virtual float renderedWidth { get; } // 0x0033F260-0x0033F310
		public virtual float renderedHeight { get; } // 0x0033F3C0-0x0033F480
		public int layoutPriority { get; } // 0x0033F540-0x0033F550

		// Events
		public static event Func<int, string, TMP_FontAsset> onFontAssetRequest {{
			add; // 0x0033A090-0x0033A180
			remove; // 0x0033A180-0x0033A270
		}
		public static event Func<int, string, TMP_SpriteAsset> onSpriteAssetRequest {{
			add; // 0x0033A270-0x0033A360
			remove; // 0x0033A360-0x0033A450
		}

		// Nested types
		protected struct CharacterSubstitution // TypeDefIndex: 2819
		{
			// Fields
			public int index; // 0x00
			public uint unicode; // 0x04

			// Constructors
			public CharacterSubstitution(int index, uint unicode); // 0x00280D10-0x00280DC0
		}

		internal enum TextInputSources // TypeDefIndex: 2820
		{
			Text = 0,
			SetText = 1,
			SetCharArray = 2,
			String = 3
		}

		protected struct UnicodeChar // TypeDefIndex: 2821
		{
			// Fields
			public int unicode; // 0x00
			public int stringIndex; // 0x04
			public int length; // 0x08
		}

		protected struct SpecialCharacter // TypeDefIndex: 2822
		{
			// Fields
			public TMP_Character character; // 0x00
			public TMP_FontAsset fontAsset; // 0x08
			public Material material; // 0x10
			public int materialIndex; // 0x18
		}

		// Constructors
		protected TMP_Text(); // 0x00354BD0-0x00355400
		static TMP_Text(); // 0x00355400-0x00355480

		// Methods
		protected virtual void LoadFontAsset(); // 0x0033F550-0x0033F560
		protected virtual void SetSharedMaterial(Material mat); // 0x0033F560-0x0033F570
		protected virtual Material GetMaterial(Material mat); // 0x0033F570-0x0033F580
		protected virtual Material[] GetSharedMaterials(); // 0x0033F580-0x0033F590
		protected virtual void SetSharedMaterials(Material[] materials); // 0x0033F590-0x0033F5A0
		protected virtual Material[] GetMaterials(Material[] mats); // 0x0033F5A0-0x0033F5B0
		protected virtual Material CreateMaterialInstance(Material source); // 0x0033F5B0-0x0033F6B0
		protected void SetVertexColorGradient(TMP_ColorGradient gradient); // 0x0033F6B0-0x0033F7F0
		protected virtual void SetFaceColor(Color32 color); // 0x0033F7F0-0x0033F800
		protected virtual void SetOutlineColor(Color32 color); // 0x0033F800-0x0033F810
		protected virtual void SetOutlineThickness(float thickness); // 0x0033F810-0x0033F820
		protected virtual void SetShaderDepth(); // 0x0033F820-0x0033F830
		protected virtual void SetCulling(); // 0x0033F830-0x0033F840
		protected virtual float GetPaddingForMaterial(); // 0x0033F840-0x0033FA30
		protected virtual float GetPaddingForMaterial(Material mat); // 0x0033FA30-0x0033FBE0
		protected virtual Vector3[] GetTextContainerLocalCorners(); // 0x0033FBE0-0x0033FBF0
		public virtual void ForceMeshUpdate(bool ignoreActiveState = false /* Metadata: 0x0015AC05 */, bool forceTextReparsing = false /* Metadata: 0x0015AC06 */); // 0x0033FBF0-0x0033FC00
		internal void SetTextInternal(string text); // 0x0033FC00-0x0033FC40
		public virtual void UpdateGeometry(Mesh mesh, int index); // 0x0033FC40-0x0033FC50
		public virtual void UpdateVertexData(TMP_VertexDataUpdateFlags flags); // 0x0033FC50-0x0033FC60
		public virtual void UpdateVertexData(); // 0x0033FC60-0x0033FC70
		public virtual void UpdateMeshPadding(); // 0x0033FC70-0x0033FC80
		public override void CrossFadeColor(Color targetColor, float duration, bool ignoreTimeScale, bool useAlpha); // 0x0033FC80-0x0033FCF0
		public override void CrossFadeAlpha(float alpha, float duration, bool ignoreTimeScale); // 0x0033FCF0-0x0033FDB0
		protected virtual void InternalCrossFadeColor(Color targetColor, float duration, bool ignoreTimeScale, bool useAlpha); // 0x0033FDB0-0x0033FDC0
		protected virtual void InternalCrossFadeAlpha(float alpha, float duration, bool ignoreTimeScale); // 0x0033FDC0-0x0033FDD0
		protected void ParseInputText(); // 0x0033AB10-0x0033AC30
		public void SetText(string text, bool syncTextInputBox = true /* Metadata: 0x0015AC07 */); // 0x0033FDD0-0x0033FDF0
		public void SetText(string text, float arg0); // 0x0033FDF0-0x0033FE10
		public void SetText(string text, float arg0, float arg1); // 0x00340860-0x00340880
		public void SetText(string text, float arg0, float arg1, float arg2); // 0x00340880-0x003408A0
		public void SetText(string text, float arg0, float arg1, float arg2, float arg3); // 0x003408A0-0x003408C0
		public void SetText(string text, float arg0, float arg1, float arg2, float arg3, float arg4); // 0x003408C0-0x003408D0
		public void SetText(string text, float arg0, float arg1, float arg2, float arg3, float arg4, float arg5); // 0x003408D0-0x003408E0
		public void SetText(string text, float arg0, float arg1, float arg2, float arg3, float arg4, float arg5, float arg6); // 0x003408E0-0x003408F0
		public void SetText(string text, float arg0, float arg1, float arg2, float arg3, float arg4, float arg5, float arg6, float arg7); // 0x0033FE10-0x00340150
		public void SetText(StringBuilder text); // 0x003408F0-0x00340950
		public void SetText(char[] text); // 0x00342080-0x00342090
		public void SetText(char[] text, int start, int length); // 0x003427D0-0x003427E0
		public void SetCharArray(char[] sourceText); // 0x00342090-0x003427D0
		public void SetCharArray(char[] sourceText, int start, int length); // 0x003427E0-0x00342FF0
		public void SetCharArray(int[] sourceText, int start, int length); // 0x00342FF0-0x003436F0
		protected int CharArrayToInternalParsingBuffer(char[] sourceText, ref UnicodeChar[] internalParsingArray); // 0x0033B890-0x0033BF70
		protected int StringToInternalParsingBuffer(string sourceText, ref UnicodeChar[] internalParsingArray); // 0x0033AC30-0x0033B890
		protected int StringBuilderToInternalParsingBuffer(StringBuilder sourceText, ref UnicodeChar[] internalParsingArray); // 0x00340950-0x003412E0
		private bool ReplaceOpeningStyleTag(ref string sourceText, int srcIndex, out int srcOffset, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x0033E500-0x0033E930
		private bool ReplaceOpeningStyleTag(ref int[] sourceText, int srcIndex, out int srcOffset, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x0033D5E0-0x0033DA10
		private bool ReplaceOpeningStyleTag(ref char[] sourceText, int srcIndex, out int srcOffset, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x0033C500-0x0033C930
		private bool ReplaceOpeningStyleTag(ref StringBuilder sourceText, int srcIndex, out int srcOffset, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x003416E0-0x00341B30
		private bool ReplaceClosingStyleTag(ref string sourceText, int srcIndex, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x0033E930-0x0033ED60
		private bool ReplaceClosingStyleTag(ref int[] sourceText, int srcIndex, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x0033DA10-0x0033DE40
		private bool ReplaceClosingStyleTag(ref char[] sourceText, int srcIndex, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x0033C930-0x0033CD60
		private bool ReplaceClosingStyleTag(ref StringBuilder sourceText, int srcIndex, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x00341B30-0x00341F80
		private TMP_Style GetStyle(int hashCode); // 0x00337AF0-0x00337DD0
		private bool InsertOpeningStyleTag(TMP_Style style, int srcIndex, ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x0033BF70-0x0033C380
		private bool InsertClosingStyleTag(ref UnicodeChar[] charBuffer, ref int writeIndex); // 0x0033CD60-0x0033D180
		private bool IsTagName(ref string text, string tag, int index); // 0x0033E390-0x0033E500
		private bool IsTagName(ref char[] text, string tag, int index); // 0x0033C380-0x0033C500
		private bool IsTagName(ref int[] text, string tag, int index); // 0x0033D460-0x0033D5E0
		private bool IsTagName(ref StringBuilder text, string tag, int index); // 0x00341590-0x003416E0
		private int GetTagHashCode(ref string text, int index, out int closeIndex); // 0x0033ED60-0x0033EEC0
		private int GetTagHashCode(ref char[] text, int index, out int closeIndex); // 0x0033DF50-0x0033E030
		private int GetTagHashCode(ref int[] text, int index, out int closeIndex); // 0x0033DE40-0x0033DF30
		private int GetTagHashCode(ref StringBuilder text, int index, out int closeIndex); // 0x00341F80-0x00342080
		private void ResizeInternalArray<T>(ref T[] array);
		private void ResizeInternalArray<T>(ref T[] array, int size);
		private void AddFloatToCharArray(float value, int padding, int precision, ref int writeIndex); // 0x00340150-0x00340730
		private void AddIntegerToCharArray(double number, int padding, ref int writeIndex); // 0x00340730-0x00340860
		protected virtual int SetArraySizes(UnicodeChar[] unicodeChars); // 0x003436F0-0x00343700
		protected virtual void GenerateTextMesh(); // 0x00343700-0x00343710
		public Vector2 GetPreferredValues(); // 0x00343710-0x00343760
		public Vector2 GetPreferredValues(float width, float height); // 0x00343760-0x003438D0
		public Vector2 GetPreferredValues(string text); // 0x00343A00-0x00343BB0
		public Vector2 GetPreferredValues(string text, float width, float height); // 0x00343BB0-0x00343D20
		protected float GetPreferredWidth(); // 0x0033A820-0x0033AB10
		private float GetPreferredWidth(Vector2 margin); // 0x003438D0-0x00343940
		protected float GetPreferredHeight(); // 0x0033EEF0-0x0033F260
		private float GetPreferredHeight(Vector2 margin); // 0x00343940-0x00343A00
		public Vector2 GetRenderedValues(); // 0x00343D20-0x00343DD0
		public Vector2 GetRenderedValues(bool onlyVisibleCharacters); // 0x00343DD0-0x00343E90
		private float GetRenderedWidth(); // 0x0033F310-0x0033F3C0
		protected float GetRenderedWidth(bool onlyVisibleCharacters); // 0x003441B0-0x00344270
		private float GetRenderedHeight(); // 0x0033F480-0x0033F540
		protected float GetRenderedHeight(bool onlyVisibleCharacters); // 0x00344270-0x00344330
		protected virtual Vector2 CalculatePreferredValues(ref float fontSize, Vector2 marginSize, bool isTextAutoSizingEnabled, bool isWordWrappingEnabled); // 0x00344330-0x00346FB0
		protected virtual Bounds GetCompoundBounds(); // 0x0034E420-0x0034E440
		protected Bounds GetTextBounds(); // 0x00339DD0-0x0033A090
		protected Bounds GetTextBounds(bool onlyVisibleCharacters); // 0x00343E90-0x003441B0
		protected void AdjustLineOffset(int startIndex, int endIndex, float offset); // 0x0034E440-0x0034E7E0
		protected void ResizeLineExtents(int size); // 0x0034E7E0-0x0034EA60
		public virtual TMP_TextInfo GetTextInfo(string text); // 0x0034EA60-0x0034EA70
		public virtual void ComputeMarginSize(); // 0x0034EA70-0x0034EA80
		protected void InsertNewLine(int i, float baseScale, float currentEmScale, float characterSpacingAdjustment, float width, float lineGap, ref bool isMaxVisibleDescenderSet, ref float maxVisibleDescender); // 0x0034EA80-0x0034EFE0
		protected void SaveWordWrappingState(ref WordWrapState state, int index, int count); // 0x0034D270-0x0034D670
		protected int RestoreWordWrappingState(ref WordWrapState state); // 0x0034CE30-0x0034D270
		protected virtual void SaveGlyphVertexInfo(float padding, float style_padding, Color32 vertexColor); // 0x0034EFE0-0x0034FDA0
		protected virtual void SaveSpriteVertexInfo(Color32 vertexColor); // 0x0034FDA0-0x00350FC0
		protected virtual void FillCharacterVertexBuffers(int i, int index_X4); // 0x00350FC0-0x00351760
		protected virtual void FillCharacterVertexBuffers(int i, int index_X4, bool isVolumetric); // 0x00351760-0x00352580
		protected virtual void FillSpriteVertexBuffers(int i, int index_X4); // 0x00352580-0x00352D20
		protected virtual void DrawUnderlineMesh(Vector3 start, Vector3 end, ref int index, float startScale, float endScale, float maxScale, float sdfScale, Color32 underlineColor); // 0x00352D20-0x00353A10
		protected virtual void DrawTextHighlight(Vector3 start, Vector3 end, ref int index, Color32 highlightColor); // 0x00353BB0-0x00354030
		protected void LoadDefaultSettings(); // 0x00354030-0x003544C0
		protected void GetSpecialCharacters(TMP_FontAsset fontAsset); // 0x003544C0-0x003544F0
		protected void GetEllipsisSpecialCharacter(TMP_FontAsset fontAsset); // 0x003544F0-0x00354840
		protected void GetUnderlineSpecialCharacter(TMP_FontAsset fontAsset); // 0x00353A10-0x00353B70
		protected void ReplaceTagWithCharacter(int[] chars, int insertionIndex, int tagLength, char c); // 0x00354840-0x003548B0
		protected TMP_FontAsset GetFontAssetForWeight(int fontWeight); // 0x003548B0-0x00354930
		protected virtual void SetActiveSubMeshes(bool state); // 0x00354930-0x00354940
		protected virtual void ClearSubMeshObjects(); // 0x00354940-0x00354950
		public virtual void ClearMesh(); // 0x00354950-0x00354960
		public virtual void ClearMesh(bool uploadGeometry); // 0x00354960-0x00354970
		public virtual string GetParsedText(); // 0x00354970-0x00354AC0
		internal bool IsSelfOrLinkedAncestor(TMP_Text targetTextComponent); // 0x00339200-0x003393E0
		internal void ReleaseLinkedTextComponent(TMP_Text targetTextComponent); // 0x00338FE0-0x00339200
		protected Vector2 PackUV(float x, float y, float scale); // 0x00353B70-0x00353BB0
		protected float PackUV(float x, float y); // 0x00354AC0-0x00354B00
		internal virtual void InternalUpdate(); // 0x00354B00-0x00354B10
		protected int HexToInt(char hex); // 0x0033DF30-0x0033DF50
		protected int GetUTF16(string text, int i); // 0x0033E250-0x0033E390
		protected int GetUTF16(int[] text, int i); // 0x0033D180-0x0033D280
		protected int GetUTF16(StringBuilder text, int i); // 0x003414A0-0x00341590
		protected int GetUTF32(string text, int i); // 0x0033E030-0x0033E250
		protected int GetUTF32(int[] text, int i); // 0x0033D280-0x0033D460
		protected int GetUTF32(StringBuilder text, int i); // 0x003412E0-0x003414A0
		protected Color32 HexCharsToColor(char[] hexChars, int tagCount); // 0x0034D670-0x0034DEE0
		protected Color32 HexCharsToColor(char[] hexChars, int startIndex, int length); // 0x0034E060-0x0034E420
		private int GetAttributeParameters(char[] chars, int startIndex, int length, ref float[] parameters); // 0x00354B10-0x00354BB0
		protected float ConvertToFloat(char[] chars, int startIndex, int length); // 0x00354BB0-0x00354BD0
		protected float ConvertToFloat(char[] chars, int startIndex, int length, out int lastIndex); // 0x0034DEE0-0x0034E060
		protected bool ValidateHtmlTag(UnicodeChar[] chars, int startIndex, out int endIndex); // 0x00346FB0-0x0034CE30
	}

	public enum TextElementType : byte // TypeDefIndex: 2823
	{
		Character = 1,
		Sprite = 2
	}

	[Serializable]
	public class TMP_TextElement // TypeDefIndex: 2824
	{
		// Fields
		[SerializeField] // 0x002547D0-0x002547E0
		protected TextElementType m_ElementType; // 0x10
		[SerializeField] // 0x002547E0-0x002547F0
		internal uint m_Unicode; // 0x14
		internal Glyph m_Glyph; // 0x18
		[SerializeField] // 0x002547F0-0x00254800
		internal uint m_GlyphIndex; // 0x20
		[SerializeField] // 0x00254800-0x00254810
		internal float m_Scale; // 0x24

		// Properties
		public uint unicode { get; set; } // 0x005CBB80-0x005CBB90 0x005CBB90-0x005CBBA0
		public Glyph glyph { get; set; } // 0x005CBBA0-0x005CBBB0 0x005CBBB0-0x005CBBC0
		public uint glyphIndex { get; set; } // 0x005CBBC0-0x005CBBD0 0x005CBBD0-0x005CBBE0
		public float scale { get; set; } // 0x005CBBE0-0x005CBBF0 0x005CBBF0-0x005CBC00

		// Constructors
		public TMP_TextElement(); // 0x005CBC00-0x005CBC10
	}

	[Serializable]
	public class TMP_TextElement_Legacy // TypeDefIndex: 2825
	{
		// Fields
		public int id; // 0x10
		public float x; // 0x14
		public float y; // 0x18
		public float width; // 0x1C
		public float height; // 0x20
		public float xOffset; // 0x24
		public float yOffset; // 0x28
		public float xAdvance; // 0x2C
		public float scale; // 0x30

		// Constructors
		public TMP_TextElement_Legacy(); // 0x005CBC10-0x005CBC20
	}

	[Serializable]
	public class TMP_TextInfo // TypeDefIndex: 2826
	{
		// Fields
		internal static Vector2 k_InfinityVectorPositive; // 0x00
		internal static Vector2 k_InfinityVectorNegative; // 0x08
		public TMP_Text textComponent; // 0x10
		public int characterCount; // 0x18
		public int spriteCount; // 0x1C
		public int spaceCount; // 0x20
		public int wordCount; // 0x24
		public int linkCount; // 0x28
		public int lineCount; // 0x2C
		public int pageCount; // 0x30
		public int materialCount; // 0x34
		public TMP_CharacterInfo[] characterInfo; // 0x38
		public TMP_WordInfo[] wordInfo; // 0x40
		public TMP_LinkInfo[] linkInfo; // 0x48
		public TMP_LineInfo[] lineInfo; // 0x50
		public TMP_PageInfo[] pageInfo; // 0x58
		public TMP_MeshInfo[] meshInfo; // 0x60
		private TMP_MeshInfo[] m_CachedMeshInfo; // 0x68

		// Constructors
		public TMP_TextInfo(); // 0x005CBC20-0x005CBCC0
		internal TMP_TextInfo(int characterCount); // 0x005CBCC0-0x005CBD70
		public TMP_TextInfo(TMP_Text textComponent); // 0x005CBD70-0x005CBE70
		static TMP_TextInfo(); // 0x005CC1A0-0x005CC1F0

		// Methods
		public void Clear(); // 0x005CBE70-0x005CBED0
		public void ClearMeshInfo(bool updateMesh); // 0x005CBED0-0x005CBF40
		public void ResetVertexLayout(bool isVolumetric); // 0x005CBF40-0x005CBFB0
		public void ClearLineInfo(); // 0x005CBFB0-0x005CC120
		internal void ClearPageInfo(); // 0x005CC120-0x005CC1A0
		public static void Resize<T>(ref T[] array, int size);
		public static void Resize<T>(ref T[] array, int size, bool isBlockAllocated);
	}

	public class TMP_TextParsingUtilities // TypeDefIndex: 2827
	{
		// Fields
		private static readonly TMP_TextParsingUtilities s_Instance; // 0x00

		// Constructors
		static TMP_TextParsingUtilities(); // 0x005CC1F0-0x005CC230
		public TMP_TextParsingUtilities(); // 0x005CC230-0x005CC240

		// Methods
		public static int GetHashCode(string s); // 0x005CC240-0x005CC3B0
		public static int GetHashCodeCaseSensitive(string s); // 0x005CC450-0x005CC500
		public static char ToUpperASCIIFast(char c); // 0x005CC3B0-0x005CC450
	}

	public enum CaretPosition // TypeDefIndex: 2828
	{
		None = 0,
		Left = 1,
		Right = 2
	}

	public static class TMP_TextUtilities // TypeDefIndex: 2829
	{
		// Fields
		private static Vector3[] m_rectWorldCorners; // 0x00

		// Constructors
		static TMP_TextUtilities(); // 0x005CEDE0-0x005CEE20

		// Methods
		public static int GetCursorIndexFromPosition(TMP_Text textComponent, Vector3 position, Camera camera, out CaretPosition cursor); // 0x005CC500-0x005CC7C0
		public static int FindNearestLine(TMP_Text text, Vector3 position, Camera camera); // 0x005CC7C0-0x005CCB00
		public static int FindNearestCharacterOnLine(TMP_Text text, Vector3 position, int line, Camera camera, bool visibleOnly); // 0x005CCB00-0x005CD0F0
		public static int FindIntersectingWord(TMP_Text text, Vector3 position, Camera camera); // 0x005CDCD0-0x005CEC90
		private static bool PointIntersectRectangle(Vector3 m, Vector3 a, Vector3 b, Vector3 c, Vector3 d); // 0x005CD680-0x005CD8F0
		public static bool ScreenPointToWorldPointInRectangle(Transform transform, Vector2 screenPoint, Camera cam, out Vector3 worldPoint); // 0x005CD0F0-0x005CD680
		public static float DistanceToLine(Vector3 a, Vector3 b, Vector3 point); // 0x005CD8F0-0x005CDCD0
		public static char ToUpperFast(char c); // 0x005CEC90-0x005CED30
		public static int GetSimpleHashCode(string s); // 0x005CED30-0x005CEDE0
	}

	public class TMP_UpdateManager // TypeDefIndex: 2830
	{
		// Fields
		private static TMP_UpdateManager s_Instance; // 0x00
		private readonly List<TMP_Text> m_LayoutRebuildQueue; // 0x10
		private readonly HashSet<int> m_LayoutQueueLookup; // 0x18
		private readonly List<TMP_Text> m_GraphicRebuildQueue; // 0x20
		private readonly HashSet<int> m_GraphicQueueLookup; // 0x28
		private readonly List<TMP_Text> m_InternalUpdateQueue; // 0x30
		private readonly HashSet<int> m_InternalUpdateLookup; // 0x38

		// Properties
		private static TMP_UpdateManager instance { get; } // 0x005CEE20-0x005CEE90

		// Constructors
		private TMP_UpdateManager(); // 0x005CEE90-0x005CF0C0

		// Methods
		internal static void RegisterTextObjectForUpdate(TMP_Text textObject); // 0x005CF0C0-0x005CF150
		private void InternalRegisterTextObjectForUpdate(TMP_Text textObject); // 0x005CF150-0x005CF1F0
		public static void RegisterTextElementForLayoutRebuild(TMP_Text element); // 0x005CF1F0-0x005CF280
		private void InternalRegisterTextElementForLayoutRebuild(TMP_Text element); // 0x005CF280-0x005CF320
		public static void RegisterTextElementForGraphicRebuild(TMP_Text element); // 0x005CF320-0x005CF3B0
		private void InternalRegisterTextElementForGraphicRebuild(TMP_Text element); // 0x005CF3B0-0x005CF450
		private void DoRebuilds(); // 0x005CF450-0x005CF670
		internal static void UnRegisterTextObjectForUpdate(TMP_Text textObject); // 0x005CF670-0x005CF700
		public static void UnRegisterTextElementForRebuild(TMP_Text element); // 0x005CF820-0x005CF9A0
		private void InternalUnRegisterTextElementForGraphicRebuild(TMP_Text element); // 0x005CF9A0-0x005CFAC0
		private void InternalUnRegisterTextElementForLayoutRebuild(TMP_Text element); // 0x005CFAC0-0x005CFBE0
		private void InternalUnRegisterTextObjectForUpdate(TMP_Text textObject); // 0x005CF700-0x005CF820
	}

	public static class TMPro_EventManager // TypeDefIndex: 2831
	{
		// Fields
		public static readonly FastAction<object, Compute_DT_EventArgs> COMPUTE_DT_EVENT; // 0x00
		public static readonly FastAction<bool, Material> MATERIAL_PROPERTY_EVENT; // 0x08
		public static readonly FastAction<bool, TMP_FontAsset> FONT_PROPERTY_EVENT; // 0x10
		public static readonly FastAction<bool, UnityEngine.Object> SPRITE_ASSET_PROPERTY_EVENT; // 0x18
		public static readonly FastAction<bool, TextMeshPro> TEXTMESHPRO_PROPERTY_EVENT; // 0x20
		public static readonly FastAction<GameObject, Material, Material> DRAG_AND_DROP_MATERIAL_EVENT; // 0x28
		public static readonly FastAction<bool> TEXT_STYLE_PROPERTY_EVENT; // 0x30
		public static readonly FastAction<TMP_ColorGradient> COLOR_GRADIENT_PROPERTY_EVENT; // 0x38
		public static readonly FastAction TMP_SETTINGS_PROPERTY_EVENT; // 0x40
		public static readonly FastAction RESOURCE_LOAD_EVENT; // 0x48
		public static readonly FastAction<bool, TextMeshProUGUI> TEXTMESHPRO_UGUI_PROPERTY_EVENT; // 0x50
		public static readonly FastAction OnPreRenderObject_Event; // 0x58
		public static readonly FastAction<UnityEngine.Object> TEXT_CHANGED_EVENT; // 0x60

		// Constructors
		static TMPro_EventManager(); // 0x005CFCC0-0x005CFF40

		// Methods
		public static void ON_TEXT_CHANGED(UnityEngine.Object obj); // 0x005CFBE0-0x005CFCC0
	}

	public class Compute_DT_EventArgs // TypeDefIndex: 2832
	{
	}

	public static class TMPro_ExtensionMethods // TypeDefIndex: 2833
	{
		// Methods
		internal static string UintToString(List<uint> unicodes); // 0x005CFF40-0x005D0060
		public static bool Compare(Color32 a, Color32 b); // 0x005D0060-0x005D00A0
		public static Color32 Multiply(Color32 c1, Color32 c2); // 0x005D00A0-0x005D0170
		public static Color MinAlpha(Color c1, Color c2); // 0x005D0170-0x005D0190
	}

	public static class TMP_Math // TypeDefIndex: 2834
	{
		// Fields
		public static Vector2 MAX_16BIT; // 0x00
		public static Vector2 MIN_16BIT; // 0x08

		// Constructors
		static TMP_Math(); // 0x00327D30-0x0032B030

		// Methods
		public static bool Approximately(float a, float b); // 0x00327D00-0x00327D30
	}

	public enum TMP_VertexDataUpdateFlags // TypeDefIndex: 2835
	{
		None = 0,
		Vertices = 1,
		Uv0 = 2,
		Uv2 = 4,
		Uv4 = 8,
		Colors32 = 16,
		All = 255
	}

	[Serializable]
	public struct VertexGradient // TypeDefIndex: 2836
	{
		// Fields
		public Color topLeft; // 0x00
		public Color topRight; // 0x10
		public Color bottomLeft; // 0x20
		public Color bottomRight; // 0x30

		// Constructors
		public VertexGradient(Color color); // 0x00267420-0x002675E0
	}

	public struct TMP_PageInfo // TypeDefIndex: 2837
	{
		// Fields
		public int firstCharacterIndex; // 0x00
		public int lastCharacterIndex; // 0x04
		public float ascender; // 0x08
		public float baseLine; // 0x0C
		public float descender; // 0x10
	}

	public struct TMP_LinkInfo // TypeDefIndex: 2838
	{
		// Fields
		public TMP_Text textComponent; // 0x00
		public int hashCode; // 0x08
		public int linkIdFirstCharacterIndex; // 0x0C
		public int linkIdLength; // 0x10
		public int linkTextfirstCharacterIndex; // 0x14
		public int linkTextLength; // 0x18
		internal char[] linkID; // 0x20

		// Methods
		internal void SetLinkID(char[] text, int startIndex, int length); // 0x00229060-0x002290C0
	}

	public struct TMP_WordInfo // TypeDefIndex: 2839
	{
		// Fields
		public TMP_Text textComponent; // 0x00
		public int firstCharacterIndex; // 0x08
		public int lastCharacterIndex; // 0x0C
		public int characterCount; // 0x10
	}

	public struct Extents // TypeDefIndex: 2840
	{
		// Fields
		internal static Extents zero; // 0x00
		internal static Extents uninitialized; // 0x10
		public Vector2 min; // 0x00
		public Vector2 max; // 0x08

		// Constructors
		public Extents(Vector2 min, Vector2 max); // 0x002562F0-0x00256300
		static Extents(); // 0x0037CD30-0x0037CE50

		// Methods
		public override string ToString(); // 0x00256300-0x00256360
	}

	public struct WordWrapState // TypeDefIndex: 2841
	{
		// Fields
		public int previous_WordBreak; // 0x00
		public int total_CharacterCount; // 0x04
		public int visible_CharacterCount; // 0x08
		public int visible_SpriteCount; // 0x0C
		public int visible_LinkCount; // 0x10
		public int firstCharacterIndex; // 0x14
		public int firstVisibleCharacterIndex; // 0x18
		public int lastCharacterIndex; // 0x1C
		public int lastVisibleCharIndex; // 0x20
		public int lineNumber; // 0x24
		public float maxCapHeight; // 0x28
		public float maxAscender; // 0x2C
		public float maxDescender; // 0x30
		public float startOfLineAscender; // 0x34
		public float maxLineAscender; // 0x38
		public float maxLineDescender; // 0x3C
		public float pageAscender; // 0x40
		public HorizontalAlignmentOptions horizontalAlignment; // 0x44
		public float marginLeft; // 0x48
		public float marginRight; // 0x4C
		public float xAdvance; // 0x50
		public float preferredWidth; // 0x54
		public float preferredHeight; // 0x58
		public float previousLineScale; // 0x5C
		public int wordCount; // 0x60
		public FontStyles fontStyle; // 0x64
		public int italicAngle; // 0x68
		public float fontScale; // 0x6C
		public float fontScaleMultiplier; // 0x70
		public float currentFontSize; // 0x74
		public float baselineOffset; // 0x78
		public float lineOffset; // 0x7C
		public bool isDrivenLineSpacing; // 0x80
		public float cSpace; // 0x84
		public float mSpace; // 0x88
		public TMP_TextInfo textInfo; // 0x90
		public TMP_LineInfo lineInfo; // 0x98
		public Color32 vertexColor; // 0xF4
		public Color32 underlineColor; // 0xF8
		public Color32 strikethroughColor; // 0xFC
		public Color32 highlightColor; // 0x100
		public TMP_FontStyleStack basicStyleStack; // 0x104
		public TMP_RichTextTagStack<int> italicAngleStack; // 0x110
		public TMP_RichTextTagStack<Color32> colorStack; // 0x128
		public TMP_RichTextTagStack<Color32> underlineColorStack; // 0x140
		public TMP_RichTextTagStack<Color32> strikethroughColorStack; // 0x158
		public TMP_RichTextTagStack<Color32> highlightColorStack; // 0x170
		public TMP_RichTextTagStack<HighlightState> highlightStateStack; // 0x188
		public TMP_RichTextTagStack<TMP_ColorGradient> colorGradientStack; // 0x1B0
		public TMP_RichTextTagStack<float> sizeStack; // 0x1C8
		public TMP_RichTextTagStack<float> indentStack; // 0x1E0
		public TMP_RichTextTagStack<FontWeight> fontWeightStack; // 0x1F8
		public TMP_RichTextTagStack<int> styleStack; // 0x210
		public TMP_RichTextTagStack<float> baselineStack; // 0x228
		public TMP_RichTextTagStack<int> actionStack; // 0x240
		public TMP_RichTextTagStack<MaterialReference> materialReferenceStack; // 0x258
		public TMP_RichTextTagStack<HorizontalAlignmentOptions> lineJustificationStack; // 0x2A0
		public int spriteAnimationID; // 0x2B8
		public TMP_FontAsset currentFontAsset; // 0x2C0
		public TMP_SpriteAsset currentSpriteAsset; // 0x2C8
		public Material currentMaterial; // 0x2D0
		public int currentMaterialIndex; // 0x2D8
		public Extents meshExtents; // 0x2DC
		public bool tagNoParsing; // 0x2EC
		public bool isNonBreakingSpace; // 0x2ED
	}

	public struct RichTextTagAttribute // TypeDefIndex: 2842
	{
		// Fields
		public int nameHashCode; // 0x00
		public int valueHashCode; // 0x04
		public TagValueType valueType; // 0x08
		public int valueStartIndex; // 0x0C
		public int valueLength; // 0x10
		public TagUnitType unitType; // 0x14
	}

	[DisallowMultipleComponent] // 0x00253850-0x002538B0
	[ExecuteAlways] // 0x00253850-0x002538B0
	[RequireComponent] // 0x00253850-0x002538B0
	[RequireComponent] // 0x00253850-0x002538B0
	public class TextMeshPro : TMP_Text, ILayoutElement // TypeDefIndex: 2843
	{
		// Fields
		[SerializeField] // 0x00254810-0x00254820
		private bool m_hasFontAssetChanged; // 0x1560
		private float m_previousLossyScaleY; // 0x1564
		[SerializeField] // 0x00254820-0x00254830
		private Renderer m_renderer; // 0x1568
		private MeshFilter m_meshFilter; // 0x1570
		private bool m_isFirstAllocation; // 0x1578
		private int m_max_characters; // 0x157C
		private int m_max_numberOfLines; // 0x1580
		protected TMP_SubMesh[] m_subTextObjects; // 0x1588
		[SerializeField] // 0x00254830-0x00254840
		private MaskingTypes m_maskType; // 0x1590
		private Matrix4x4 m_EnvMapMatrix; // 0x1594
		private Vector3[] m_RectTransformCorners; // 0x15D8
		[NonSerialized]
		private bool m_isRegisteredForEvents; // 0x15E0
		private bool m_currentAutoSizeMode; // 0x15E1

		// Properties
		public int sortingLayerID { get; set; } // 0x005E6770-0x005E69B0 0x005E6AC0-0x005E6D00
		public int sortingOrder { get; set; } // 0x005E6D00-0x005E6F40 0x005E6F40-0x005E7180
		public override bool autoSizeTextContainer { get; set; } // 0x005E7180-0x005E7190 0x005E7190-0x005E7260
		[Obsolete] // 0x00254AA0-0x00254AC0
		public TextContainer textContainer { get; } // 0x005E7260-0x005E7270
		public new Transform transform { get; } // 0x005D2430-0x005D2540
		public Renderer renderer { get; } // 0x005E69B0-0x005E6AC0
		public override Mesh mesh { get; } // 0x005E7270-0x005E7520
		public MeshFilter meshFilter { get; } // 0x005D27A0-0x005D28B0
		public MaskingTypes maskType { get; set; } // 0x005E7520-0x005E7530 0x005E7530-0x005E7540

		// Constructors
		public TextMeshPro(); // 0x005E8EE0-0x005E8F80

		// Methods
		protected override void Awake(); // 0x005D1BF0-0x005D2430
		protected override void OnEnable(); // 0x005D2540-0x005D27A0
		protected override void OnDisable(); // 0x005D28B0-0x005D29C0
		protected override void OnDestroy(); // 0x005D29C0-0x005D2B60
		protected override void LoadFontAsset(); // 0x005D2B60-0x005D3630
		private void UpdateEnvMapMatrix(); // 0x005D3630-0x005D3B90
		private void SetMask(MaskingTypes maskType); // 0x005D3B90-0x005D3E20
		private void SetMaskCoordinates(Vector4 coords); // 0x005D3E20-0x005D3F00
		private void SetMaskCoordinates(Vector4 coords, float softX, float softY); // 0x005D3F00-0x005D40B0
		private void EnableMasking(); // 0x005D40B0-0x005D43A0
		private void DisableMasking(); // 0x005D45C0-0x005D48B0
		private void UpdateMask(); // 0x005D44B0-0x005D45C0
		protected override Material GetMaterial(Material mat); // 0x005D48B0-0x005D4A40
		protected override Material[] GetMaterials(Material[] mats); // 0x005D4A40-0x005D4D10
		protected override void SetSharedMaterial(Material mat); // 0x005D4D10-0x005D4D50
		protected override Material[] GetSharedMaterials(); // 0x005D4D50-0x005D5040
		protected override void SetSharedMaterials(Material[] materials); // 0x005D5040-0x005D5710
		protected override void SetOutlineThickness(float thickness); // 0x005D5710-0x005D59C0
		protected override void SetFaceColor(Color32 color); // 0x005D59C0-0x005D5C20
		protected override void SetOutlineColor(Color32 color); // 0x005D5C20-0x005D5E80
		private void CreateMaterialInstance(); // 0x005D43A0-0x005D44B0
		protected override void SetShaderDepth(); // 0x005D5E80-0x005D60B0
		protected override void SetCulling(); // 0x005D60B0-0x005D6720
		private void SetPerspectiveCorrection(); // 0x005D6720-0x005D6840
		protected override int SetArraySizes(UnicodeChar[] unicodeChars); // 0x005D6840-0x005D9050
		public override void ComputeMarginSize(); // 0x005D9050-0x005D9240
		protected override void OnDidApplyAnimationProperties(); // 0x005D9240-0x005D9270
		protected override void OnTransformParentChanged(); // 0x005D9270-0x005D92A0
		protected override void OnRectTransformDimensionsChange(); // 0x005D92A0-0x005D95A0
		internal override void InternalUpdate(); // 0x005D95A0-0x005D9690
		private void OnPreRenderObject(); // 0x005D9A00-0x005D9F10
		protected override void GenerateTextMesh(); // 0x005D9F10-0x005E52F0
		protected override Vector3[] GetTextContainerLocalCorners(); // 0x005E52F0-0x005E5420
		private void SetMeshFilters(bool state); // 0x005E5420-0x005E5B30
		protected override void SetActiveSubMeshes(bool state); // 0x005E5B30-0x005E5D80
		protected override void ClearSubMeshObjects(); // 0x005E5D80-0x005E5FB0
		protected override Bounds GetCompoundBounds(); // 0x005E5FB0-0x005E6770
		private void UpdateSDFScale(float scaleDelta); // 0x005D9690-0x005D9A00
		public void SetMask(MaskingTypes type, Vector4 maskCoords); // 0x005E7540-0x005E7620
		public void SetMask(MaskingTypes type, Vector4 maskCoords, float softnessX, float softnessY); // 0x005E7620-0x005E7670
		public override void SetVerticesDirty(); // 0x005E7670-0x005E77F0
		public override void SetLayoutDirty(); // 0x005E77F0-0x005E78F0
		public override void SetMaterialDirty(); // 0x005E78F0-0x005E7910
		public override void SetAllDirty(); // 0x005E7910-0x005E7960
		public override void Rebuild(CanvasUpdate update); // 0x005E7960-0x005E7B00
		protected override void UpdateMaterial(); // 0x005E7B00-0x005E7F80
		public override void UpdateMeshPadding(); // 0x005E7F80-0x005E8100
		public override void ForceMeshUpdate(bool ignoreActiveState = false /* Metadata: 0x0015AC42 */, bool forceTextReparsing = false /* Metadata: 0x0015AC43 */); // 0x005E8100-0x005E8140
		public override TMP_TextInfo GetTextInfo(string text); // 0x005E8140-0x005E81B0
		public override void ClearMesh(bool updateMesh); // 0x005E81B0-0x005E8360
		public override void UpdateGeometry(Mesh mesh, int index); // 0x005E8360-0x005E8380
		public override void UpdateVertexData(TMP_VertexDataUpdateFlags flags); // 0x005E8380-0x005E8750
		public override void UpdateVertexData(); // 0x005E8750-0x005E8AF0
		public void UpdateFontAsset(); // 0x005E8AF0-0x005E8B10
		public void CalculateLayoutInputHorizontal(); // 0x005E8B10-0x005E8D00
		public void CalculateLayoutInputVertical(); // 0x005E8D00-0x005E8EE0
	}

	[DisallowMultipleComponent] // 0x002538B0-0x00253910
	[ExecuteAlways] // 0x002538B0-0x00253910
	[RequireComponent] // 0x002538B0-0x00253910
	[RequireComponent] // 0x002538B0-0x00253910
	public class TextMeshProUGUI : TMP_Text, ILayoutElement // TypeDefIndex: 2844
	{
		// Fields
		[SerializeField] // 0x00254840-0x00254850
		private bool m_hasFontAssetChanged; // 0x1560
		protected TMP_SubMeshUI[] m_subTextObjects; // 0x1568
		private float m_previousLossyScaleY; // 0x1570
		private Vector3[] m_RectTransformCorners; // 0x1578
		private CanvasRenderer m_canvasRenderer; // 0x1580
		private Canvas m_canvas; // 0x1588
		private bool m_isFirstAllocation; // 0x1590
		private int m_max_characters; // 0x1594
		[SerializeField] // 0x00254850-0x00254860
		private Material m_baseMaterial; // 0x1598
		private bool m_isScrollRegionSet; // 0x15A0
		private int m_stencilID; // 0x15A4
		[SerializeField] // 0x00254860-0x00254870
		private Vector4 m_maskOffset; // 0x15A8
		private Matrix4x4 m_EnvMapMatrix; // 0x15B8
		[NonSerialized]
		private bool m_isRegisteredForEvents; // 0x15F8
		private bool m_isRebuildingLayout; // 0x15F9
		private Coroutine m_DelayedGraphicRebuild; // 0x1600
		private Coroutine m_DelayedMaterialRebuild; // 0x1608

		// Properties
		public override Material materialForRendering { get; } // 0x0067A170-0x0067A1D0
		public override bool autoSizeTextContainer { get; set; } // 0x0067A1D0-0x0067A1E0 0x0067A1E0-0x0067A270
		public override Mesh mesh { get; } // 0x0067A270-0x0067A280
		public new CanvasRenderer canvasRenderer { get; } // 0x0067A280-0x0067A390
		public Vector4 maskOffset { get; set; } // 0x0067B4C0-0x0067B4E0 0x0067B4E0-0x0067B500

		// Nested types
		private sealed class <DelayedGraphicRebuild>d__67 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2845
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public TextMeshProUGUI <>4__this; // 0x20

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00254A10-0x00254A20 */ get; } // 0x00AC7E20-0x00AC7E30
			object IEnumerator.Current { [DebuggerHidden] /* 0x00254A20-0x00254A30 */ get; } // 0x00AC7E30-0x00AC7E40

			// Constructors
			[DebuggerHidden] // 0x002549F0-0x00254A00
			public <DelayedGraphicRebuild>d__67(int <>1__state); // 0x00AC7D10-0x00AC7D20

			// Methods
			[DebuggerHidden] // 0x00254A00-0x00254A10
			void IDisposable.Dispose(); // 0x00AC7D20-0x00AC7D30
			private bool MoveNext(); // 0x00AC7D30-0x00AC7E20
		}

		private sealed class <DelayedMaterialRebuild>d__68 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2846
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public TextMeshProUGUI <>4__this; // 0x20

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00254A50-0x00254A60 */ get; } // 0x00AC7F50-0x00AC7F60
			object IEnumerator.Current { [DebuggerHidden] /* 0x00254A60-0x00254A70 */ get; } // 0x00AC7F60-0x00AC7F70

			// Constructors
			[DebuggerHidden] // 0x00254A30-0x00254A40
			public <DelayedMaterialRebuild>d__68(int <>1__state); // 0x00AC7E40-0x00AC7E50

			// Methods
			[DebuggerHidden] // 0x00254A40-0x00254A50
			void IDisposable.Dispose(); // 0x00AC7E50-0x00AC7E60
			private bool MoveNext(); // 0x00AC7E60-0x00AC7F50
		}

		// Constructors
		public TextMeshProUGUI(); // 0x0067C790-0x0067C840

		// Methods
		protected override void Awake(); // 0x00665090-0x00665660
		protected override void OnEnable(); // 0x00665660-0x00665760
		protected override void OnDisable(); // 0x006658F0-0x00665BF0
		protected override void OnDestroy(); // 0x00665BF0-0x00665E40
		protected override void LoadFontAsset(); // 0x00665E40-0x00666B50
		private Canvas GetCanvas(); // 0x00665760-0x006658F0
		private void UpdateEnvMapMatrix(); // 0x00666B50-0x006670B0
		private void EnableMasking(); // 0x006670B0-0x00667450
		private void DisableMasking(); // 0x00667C30-0x00667E20
		private void UpdateMask(); // 0x00667450-0x00667C30
		protected override Material GetMaterial(Material mat); // 0x00667E20-0x00667FE0
		protected override Material[] GetMaterials(Material[] mats); // 0x00667FE0-0x006682B0
		protected override void SetSharedMaterial(Material mat); // 0x006682B0-0x006682F0
		protected override Material[] GetSharedMaterials(); // 0x006682F0-0x006685F0
		protected override void SetSharedMaterials(Material[] materials); // 0x006685F0-0x00668E10
		protected override void SetOutlineThickness(float thickness); // 0x00668E10-0x006691A0
		protected override void SetFaceColor(Color32 color); // 0x006691A0-0x006693C0
		protected override void SetOutlineColor(Color32 color); // 0x006693C0-0x006695E0
		protected override void SetShaderDepth(); // 0x006695E0-0x006698A0
		protected override void SetCulling(); // 0x006698A0-0x00669FC0
		private void SetPerspectiveCorrection(); // 0x00669FC0-0x0066A0E0
		private void SetMeshArrays(int size); // 0x0066A0E0-0x0066A1A0
		protected override int SetArraySizes(UnicodeChar[] unicodeChars); // 0x0066A1A0-0x0066CDB0
		public override void ComputeMarginSize(); // 0x0066CDB0-0x0066CFA0
		protected override void OnDidApplyAnimationProperties(); // 0x0066CFA0-0x0066CFE0
		protected override void OnCanvasHierarchyChanged(); // 0x0066CFE0-0x0066D1B0
		protected override void OnTransformParentChanged(); // 0x0066D1B0-0x0066D1F0
		protected override void OnRectTransformDimensionsChange(); // 0x0066D1F0-0x0066D580
		internal override void InternalUpdate(); // 0x0066D710-0x0066D800
		private void OnPreRenderCanvas(); // 0x0066DC60-0x0066E100
		protected override void GenerateTextMesh(); // 0x0066E100-0x00679630
		protected override Vector3[] GetTextContainerLocalCorners(); // 0x00679630-0x00679760
		protected override void SetActiveSubMeshes(bool state); // 0x00679760-0x006799B0
		protected override Bounds GetCompoundBounds(); // 0x006799B0-0x0067A170
		private void UpdateSDFScale(float scaleDelta); // 0x0066D800-0x0066DC60
		public void CalculateLayoutInputHorizontal(); // 0x0067A390-0x0067A4B0
		public void CalculateLayoutInputVertical(); // 0x0067A4B0-0x0067A5E0
		public override void SetVerticesDirty(); // 0x0067A5E0-0x0067A830
		public override void SetLayoutDirty(); // 0x0067A880-0x0067A9D0
		public override void SetMaterialDirty(); // 0x0067A9D0-0x0067AC20
		public override void SetAllDirty(); // 0x0067AC70-0x0067ACC0
		private IEnumerator DelayedGraphicRebuild(); // 0x0067A830-0x0067A880
		private IEnumerator DelayedMaterialRebuild(); // 0x0067AC20-0x0067AC70
		public override void Rebuild(CanvasUpdate update); // 0x0067ACC0-0x0067AE60
		private void UpdateSubObjectPivot(); // 0x0066D580-0x0066D710
		public override Material GetModifiedMaterial(Material baseMaterial); // 0x0067AE60-0x0067B150
		protected override void UpdateMaterial(); // 0x0067B150-0x0067B4C0
		public override void RecalculateClipping(); // 0x0067B500-0x0067B510
		public override void RecalculateMasking(); // 0x0067B510-0x0067B530
		public override void Cull(Rect clipRect, bool validRect); // 0x0067B530-0x0067B770
		public override void UpdateMeshPadding(); // 0x0067B770-0x0067B8F0
		protected override void InternalCrossFadeColor(Color targetColor, float duration, bool ignoreTimeScale, bool useAlpha); // 0x0067B8F0-0x0067B9B0
		protected override void InternalCrossFadeAlpha(float alpha, float duration, bool ignoreTimeScale); // 0x0067B9B0-0x0067BA60
		public override void ForceMeshUpdate(bool ignoreActiveState = false /* Metadata: 0x0015AC44 */, bool forceTextReparsing = false /* Metadata: 0x0015AC45 */); // 0x0067BA60-0x0067BAA0
		public override TMP_TextInfo GetTextInfo(string text); // 0x0067BAA0-0x0067BC10
		public override void ClearMesh(); // 0x0067BC10-0x0067BE30
		public override void UpdateGeometry(Mesh mesh, int index); // 0x0067BE30-0x0067BEF0
		public override void UpdateVertexData(TMP_VertexDataUpdateFlags flags); // 0x0067BEF0-0x0067C340
		public override void UpdateVertexData(); // 0x0067C340-0x0067C770
		public void UpdateFontAsset(); // 0x0067C770-0x0067C790
	}

	public enum TextContainerAnchors // TypeDefIndex: 2847
	{
		TopLeft = 0,
		Top = 1,
		TopRight = 2,
		Left = 3,
		Middle = 4,
		Right = 5,
		BottomLeft = 6,
		Bottom = 7,
		BottomRight = 8,
		Custom = 9
	}

	[RequireComponent] // 0x00253910-0x00253950
	public class TextContainer : UIBehaviour // TypeDefIndex: 2848
	{
		// Fields
		private bool m_hasChanged; // 0x18
		[SerializeField] // 0x00254870-0x00254880
		private Vector2 m_pivot; // 0x1C
		[SerializeField] // 0x00254880-0x00254890
		private TextContainerAnchors m_anchorPosition; // 0x24
		[SerializeField] // 0x00254890-0x002548A0
		private Rect m_rect; // 0x28
		private bool m_isDefaultWidth; // 0x38
		private bool m_isDefaultHeight; // 0x39
		private bool m_isAutoFitting; // 0x3A
		private Vector3[] m_corners; // 0x40
		private Vector3[] m_worldCorners; // 0x48
		[SerializeField] // 0x002548A0-0x002548B0
		private Vector4 m_margins; // 0x50
		private RectTransform m_rectTransform; // 0x60
		private static Vector2 k_defaultSize; // 0x00
		private TextMeshPro m_textMeshPro; // 0x68

		// Properties
		public bool hasChanged { get; set; } // 0x005D0190-0x005D01A0 0x005D01A0-0x005D01B0
		public Vector2 pivot { get; set; } // 0x005D01B0-0x005D01C0 0x005D01C0-0x005D02C0
		public TextContainerAnchors anchorPosition { get; set; } // 0x005D0CB0-0x005D0CC0 0x005D0CC0-0x005D0DE0
		public Rect rect { get; set; } // 0x005D0ED0-0x005D0EE0 0x005D0EE0-0x005D0F30
		public Vector2 size { get; set; } // 0x005D0F30-0x005D0F40 0x005D0F40-0x005D1080
		public float width { get; set; } // 0x005D10B0-0x005D10C0 0x005D10C0-0x005D1100
		public float height { get; set; } // 0x005D1100-0x005D1110 0x005D1110-0x005D1150
		public bool isDefaultWidth { get; } // 0x005D1150-0x005D1160
		public bool isDefaultHeight { get; } // 0x005D1160-0x005D1170
		public bool isAutoFitting { get; set; } // 0x005D1170-0x005D1180 0x005D1180-0x005D1190
		public Vector3[] corners { get; } // 0x005D1190-0x005D11A0
		public Vector3[] worldCorners { get; } // 0x005D11A0-0x005D11B0
		public Vector4 margins { get; set; } // 0x005D11B0-0x005D11C0 0x005D11C0-0x005D1300
		public RectTransform rectTransform { get; } // 0x005D1300-0x005D1400
		public TextMeshPro textMeshPro { get; } // 0x005D1400-0x005D1500

		// Constructors
		public TextContainer(); // 0x005D1B20-0x005D1BB0
		static TextContainer(); // 0x005D1BB0-0x005D1BF0

		// Methods
		protected override void Awake(); // 0x005D1500-0x005D15C0
		protected override void OnEnable(); // 0x005D15C0-0x005D15D0
		protected override void OnDisable(); // 0x005D15D0-0x005D15E0
		private void OnContainerChanged(); // 0x005D06C0-0x005D0A60
		protected override void OnRectTransformDimensionsChange(); // 0x005D15E0-0x005D1B20
		private void SetRect(Vector2 size); // 0x005D1080-0x005D10B0
		private void UpdateCorners(); // 0x005D0A60-0x005D0CB0
		private Vector2 GetPivot(TextContainerAnchors anchor); // 0x005D0DE0-0x005D0ED0
		private TextContainerAnchors GetAnchorPosition(Vector2 pivot); // 0x005D02C0-0x005D06C0
	}
}

internal sealed class <PrivateImplementationDetails> // TypeDefIndex: 2849
{
	// Fields
	internal static readonly __StaticArrayInitTypeSize=12 7BBE37982E6C057ED87163CAFC7FD6E5E42EEA46; // 0x00

	// Nested types
	private struct __StaticArrayInitTypeSize=12 // TypeDefIndex: 2850
	{
	}
}

namespace VisualDesignCafe.Rendering
{
	public class FrustumCuller // TypeDefIndex: 2852
	{
		// Fields
		private const int PlaneCount = 6; // Metadata: 0x0015AC7A
		private Plane[] _planes; // 0x10
		private Vector3[] _absNormals; // 0x18
		private Vector3[] _planeNormal; // 0x20
		private float[] _planeDistance; // 0x28

		// Nested types
		public struct Box // TypeDefIndex: 2853
		{
			// Fields
			public Vector3 Center; // 0x00
			public Vector3 Extends; // 0x0C
		}

		// Constructors
		public FrustumCuller(); // 0x00639410-0x00639490

		// Methods
		public void SetPlanes(Plane[] planes); // 0x0063B970-0x0063BAE0
		public bool IsInFrustum(Box box); // 0x0063D720-0x0063DA30
	}
}

namespace VisualDesignCafe.Rendering.Nature
{
	internal class BuildQueue // TypeDefIndex: 2854
	{
		// Fields
		private Action OnFinished; // 0x10
		private readonly List<CellBuildData> _cellsToRebuild; // 0x18
		private bool _log; // 0x20
		private bool _abort; // 0x21
		private int _processorCount; // 0x24

		// Properties
		public int ThreadCount { set; } // 0x006240F0-0x00624150

		// Events
		public event Action OnFinished {{
			add; // 0x00623FD0-0x00624060
			remove; // 0x00624060-0x006240F0
		}

		// Nested types
		public struct CellBuildData // TypeDefIndex: 2855
		{
			// Fields
			public CachedTerrainData TerrainData; // 0x00
			public Cell Cell; // 0x08
			public bool[] DirtyLayers; // 0x10
			public TerrainChangedFlags Flags; // 0x18

			// Properties
			public bool RebuildAll { get; } // 0x002872B0-0x002872C0
			public bool RebuildHeightmap { get; } // 0x002872C0-0x002872D0

			// Constructors
			public CellBuildData(CachedTerrainData terrainData, Cell cell, bool[] dirtyLayers, TerrainChangedFlags flags); // 0x002872D0-0x00287A30
		}

		private sealed class <>c__DisplayClass16_0 // TypeDefIndex: 2856
		{
			// Fields
			public Vector3 referencePosition; // 0x10

			// Constructors
			public <>c__DisplayClass16_0(); // 0x00B0A200-0x00B0A210

			// Methods
			internal int <Sort>b__0(CellBuildData x, CellBuildData y); // 0x00B0A210-0x00B0A390
		}

		private sealed class <>c__DisplayClass17_0 // TypeDefIndex: 2857
		{
			// Fields
			public int usedThreads; // 0x10
			public int rebuiltCells; // 0x14
			public int finishedCount; // 0x18
			public int threadCount; // 0x1C
			public BuildQueue <>4__this; // 0x20
			public Stopwatch timer; // 0x28
			public WaitCallback <>9__1; // 0x30

			// Constructors
			public <>c__DisplayClass17_0(); // 0x00B0A390-0x00B0A3A0

			// Methods
			internal void <Build>g__onFinished|0(int count); // 0x00B0A3A0-0x00B0A3F0
			internal void <Build>b__1(object obj); // 0x00B0A3F0-0x00B0A4E0
		}

		// Constructors
		public BuildQueue(); // 0x00624150-0x00624220

		// Methods
		public CellBuildData[] GetQueue(); // 0x00624220-0x00624350
		public void Clear(); // 0x00624350-0x00624430
		public void Dispose(); // 0x00624430-0x00624440
		public void AddRange(IEnumerable<CellBuildData> cells); // 0x00624440-0x00624530
		public void Sort(Vector3 referencePosition); // 0x00624530-0x00624690
		public void Build(); // 0x00624690-0x00624760
		private void BuildAll(Action<int> finishedCallback); // 0x00624760-0x006247C0
		private bool BuildNext(); // 0x006247C0-0x006248F0
		private bool RebuildCellIfChanged(CellBuildData cell); // 0x00624A60-0x00624AB0
		private CellBuildData GetNextCell(); // 0x006248F0-0x00624A60
	}

	public class CachedTerrainData // TypeDefIndex: 2858
	{
		// Fields
		private float <Density>k__BackingField; // 0x10
		private Bounds <Bounds>k__BackingField; // 0x14
		private Vector3 <Position>k__BackingField; // 0x2C
		private Vector3 <Size>k__BackingField; // 0x38
		private int <DetailWidth>k__BackingField; // 0x44
		private int <DetailHeight>k__BackingField; // 0x48
		private TerrainDetail[] <DetailPrototypes>k__BackingField; // 0x50
		private int[,][] <DetailTextures>k__BackingField; // 0x58
		private int[,][] <PreviousDetailTextures>k__BackingField; // 0x60
		private int <HeightmapHeight>k__BackingField; // 0x68
		private int <HeightmapWidth>k__BackingField; // 0x6C
		private float[,] <Heights>k__BackingField; // 0x70
		private float[,] <PreviousHeights>k__BackingField; // 0x78
		private Vector3 <HeightmapScale>k__BackingField; // 0x80
		private Material <GrassBillboardMaterial>k__BackingField; // 0x90
		private readonly object _lock; // 0x98

		// Properties
		public float Density { get; private set; } // 0x00628EA0-0x00628EB0 0x00628EB0-0x00628EC0
		public Bounds Bounds { get; private set; } // 0x00628EC0-0x00628EE0 0x00628EE0-0x00628F00
		public Vector3 Position { get; private set; } // 0x00628F00-0x00628F10 0x00628F10-0x00628F20
		public Vector3 Size { get; private set; } // 0x00628F20-0x00628F30 0x00628F30-0x00628F40
		public int DetailWidth { get; private set; } // 0x00628F40-0x00628F50 0x00628F50-0x00628F60
		public int DetailHeight { get; private set; } // 0x00628F60-0x00628F70 0x00628F70-0x00628F80
		public TerrainDetail[] DetailPrototypes { get; private set; } // 0x00628F80-0x00628F90 0x00628F90-0x00628FA0
		public int[,][] DetailTextures { get; private set; } // 0x00628FA0-0x00628FB0 0x00628FB0-0x00628FC0
		public int[,][] PreviousDetailTextures { get; private set; } // 0x00628FC0-0x00628FD0 0x00628FD0-0x00628FE0
		public int HeightmapHeight { get; private set; } // 0x00628FE0-0x00628FF0 0x00628FF0-0x00629000
		public int HeightmapWidth { get; private set; } // 0x00629000-0x00629010 0x00629010-0x00629020
		public float[,] Heights { get; private set; } // 0x00629020-0x00629030 0x00629030-0x00629040
		public float[,] PreviousHeights { get; private set; } // 0x00629040-0x00629050 0x00629050-0x00629060
		public Vector3 HeightmapScale { get; private set; } // 0x00629060-0x00629080 0x00629080-0x00629090

		// Nested types
		private sealed class <>c__DisplayClass66_0 // TypeDefIndex: 2859
		{
			// Fields
			public CachedTerrainData <>4__this; // 0x10
			public float minX; // 0x18
			public float minY; // 0x1C
			public float maxX; // 0x20
			public float maxY; // 0x24
			public bool hasModifications; // 0x28

			// Constructors
			public <>c__DisplayClass66_0(); // 0x00B0A4E0-0x00B0A4F0

			// Methods
			internal void <GetModifiedHeightmapRect>b__0(int x); // 0x00B0A4F0-0x00B0A730
		}

		private sealed class <>c__DisplayClass68_0 // TypeDefIndex: 2860
		{
			// Fields
			public int[,] detailTexture; // 0x10
			public int[,] previousDetailTexture; // 0x18
			public CachedTerrainData <>4__this; // 0x20
			public float minX; // 0x28
			public float minY; // 0x2C
			public float maxX; // 0x30
			public float maxY; // 0x34
			public bool hasModifications; // 0x38

			// Constructors
			public <>c__DisplayClass68_0(); // 0x00B0A730-0x00B0A740

			// Methods
			internal void <GetModifiedDetailMapRect>b__0(int x); // 0x00B0A740-0x00B0A980
		}

		// Constructors
		public CachedTerrainData(CachedTerrainData other); // 0x00629090-0x006294B0
		public CachedTerrainData(Terrain terrain, Material billboardMaterial); // 0x006294B0-0x00629520

		// Methods
		internal void Dispose(); // 0x00632CA0-0x00632D00
		internal void RefreshPrototypes(Terrain terrain, Camera camera, Material billboardMaterial, out bool flushEverything); // 0x00632D00-0x00632F10
		internal void CopyFrom(Terrain terrain, Material billboardMaterial, out bool flushEverything); // 0x00629520-0x0062A520
		internal Rect GetModifiedHeightmapRect(bool exact); // 0x00632F80-0x006332A0
		internal Rect GetModifiedDetailMapRect(bool[] dirtyLayers, bool exact); // 0x006332A0-0x006334E0
		internal Rect GetModifiedDetailMapRect(int layer, bool exact); // 0x006334E0-0x00633840
		internal float GetHeight(int x, int y); // 0x00628DD0-0x00628EA0
		internal float GetInterpolatedHeight(float x, float y); // 0x006289E0-0x00628B10
		internal Vector3 GetInterpolatedNormal(float x, float y); // 0x00628B10-0x00628DD0
		internal bool[] GetDirtyLayers(); // 0x00633840-0x006339A0
		private void CopyDetailTextureFrom(TerrainData data, int layer); // 0x0062DB20-0x0062DE40
		private void CopyHeightmapFrom(TerrainData data); // 0x00632F10-0x00632F50
		private int Hash(int[,] array); // 0x006339A0-0x00633AE0
	}

	public class Cell // TypeDefIndex: 2861
	{
		// Fields
		private BuildStatus <IsBuilt>k__BackingField; // 0x10
		private bool <BuildIsDirty>k__BackingField; // 0x14
		private bool <IsBuilding>k__BackingField; // 0x15
		private Dictionary<int, VisibilityState> <IsRendered>k__BackingField; // 0x18
		private Bounds <WorldBounds>k__BackingField; // 0x20
		private Bounds <LocalBounds>k__BackingField; // 0x38
		private float <LocalBoundsExtends>k__BackingField; // 0x50
		private Rect <Rect>k__BackingField; // 0x54
		private DetailLayer[] <DetailLayers>k__BackingField; // 0x68
		public readonly object DetailLayersLock; // 0x70
		private float <SqrDistanceToCamera>k__BackingField; // 0x78
		private readonly PlacementAlgorithm _placementAlgorithm; // 0x80
		private CachedTerrainData _terrainData; // 0x88
		private Vector3 _pixelToTerrain; // 0x90
		private bool _hasHeightBounds; // 0x9C
		private float[,] _cachedDistances; // 0xA0
		private float _cachedDistanceToCenter; // 0xA8

		// Properties
		public BuildStatus IsBuilt { get; private set; } // 0x00633AE0-0x00633AF0 0x00633AF0-0x00633B00
		public bool BuildIsDirty { get; set; } // 0x00633B00-0x00633B10 0x00633B10-0x00633B20
		public bool IsBuilding { get; internal set; } // 0x00633B20-0x00633B30 0x00633B30-0x00633B40
		public Dictionary<int, VisibilityState> IsRendered { get; internal set; } // 0x00633B40-0x00633B50 0x00633B50-0x00633B60
		public Bounds WorldBounds { get; private set; } // 0x00633B60-0x00633B80 0x00633B80-0x00633BA0
		public Bounds LocalBounds { get; private set; } // 0x00633BA0-0x00633BC0 0x00633BC0-0x00633BE0
		public float LocalBoundsExtends { get; private set; } // 0x00633BE0-0x00633BF0 0x00633BF0-0x00633C00
		public Rect Rect { get; private set; } // 0x00633C00-0x00633C10 0x00633C10-0x00633C20
		internal DetailLayer[] DetailLayers { get; private set; } // 0x00633C20-0x00633C30 0x00633C30-0x00633C40
		public float SqrDistanceToCamera { get; set; } // 0x00633C40-0x00633C50 0x00633C50-0x00633C60

		// Nested types
		public enum VisibilityState // TypeDefIndex: 2862
		{
			Hidden = 0,
			VisibleOrChanged = 1,
			Rendered = 2
		}

		public enum BuildStatus // TypeDefIndex: 2863
		{
			None = 0,
			Partial = 1,
			Full = 2
		}

		// Constructors
		public Cell(CachedTerrainData terrainData, Bounds bounds); // 0x00633C60-0x00634650

		// Methods
		internal VisibilityState GetIsRendered(int cameraHash); // 0x00634700-0x00634790
		internal void ClearCachedDistances(); // 0x00634790-0x00634870
		internal float GetCachedDistance(Vector3 cameraPosition, Vector3 terrainPosition); // 0x00634870-0x006349E0
		internal float GetCachedDistanceSqr(int x, int z, Bounds localBounds, Vector3 cameraPosition, Vector3 terrainPosition); // 0x006349E0-0x00634BC0
		internal void OnDrawGizmos(); // 0x00634BC0-0x00634CE0
		internal void Dispose(); // 0x00634ED0-0x00634FE0
		internal void Clear(); // 0x00624C60-0x00624D60
		internal void Refresh(); // 0x00624AB0-0x00624C60
		internal int Build(int[,][] detailTextures, bool[] dirtyLayers, float density); // 0x00624D60-0x00625930
		private bool BuildDetailLayer(int[,] detailTexture, Rect pixelRange, int layer, float density, ref float minHeight, ref float maxHeight); // 0x00625930-0x006267E0
		private bool BuildDetail(TerrainDetail detail, float pixelX, float pixelY, Rect pixelRange, int[,] detailTexture, int layer, DetailLayer detailLayer, float density, out float height); // 0x006350A0-0x00635AB0
	}

	public class CellStreamer // TypeDefIndex: 2864
	{
		// Fields
		public StreamSettings Settings; // 0x10
		private readonly List<Camera> _cameras; // 0x28
		private readonly Cell[] _cellsToStream; // 0x30
		private readonly Grid _terrainCells; // 0x38
		private readonly CachedTerrainData _terrainData; // 0x40
		private Camera[] _sceneCameras; // 0x48
		private List<Camera> _sceneViewCameras; // 0x50
		private int _totalCellsInRange; // 0x58
		private int _totalCellsBuilt; // 0x5C
		private Dictionary<Camera, string> _cameraNameLookup; // 0x60

		// Nested types
		public struct StreamSettings // TypeDefIndex: 2865
		{
			// Fields
			public bool Stream; // 0x00
			public Vector2 ReferencePosition; // 0x04
			public float StreamInDistance; // 0x0C
			public float StreamOutDistance; // 0x10
			public float ProcessorLimit; // 0x14
		}

		// Constructors
		public CellStreamer(Grid cells, CachedTerrainData terrainData); // 0x00635AB0-0x00635C10

		// Methods
		public float GetVisibleCellBuildProgress(); // 0x00635C10-0x00635C30
		public void Stream(Camera camera); // 0x00635C30-0x00635F90
		private void Stream(List<Camera> cameras, Cell[,] cells); // 0x00636060-0x00636D30
		private string CameraName(Camera camera); // 0x00635F90-0x00636060
	}

	internal class CpuCuller // TypeDefIndex: 2866
	{
		// Fields
		private bool <IsCached>k__BackingField; // 0x10
		private readonly Cell _cell; // 0x18
		private readonly FrustumCuller _frustumCuller; // 0x20
		private float _distanceToCamera; // 0x28
		private float _closestPoint; // 0x2C
		private float _furthestPoint; // 0x30

		// Properties
		public bool IsCached { get; private set; } // 0x00637000-0x00637010 0x00637010-0x00637020

		// Constructors
		public CpuCuller(Cell cell, FrustumCuller frustumCuller); // 0x00637020-0x006370C0

		// Methods
		public CpuCuller Cache(Vector3 terrainPosition, Vector3 cameraPosition); // 0x006370C0-0x00637280
		public bool CellIsInFadeOutRange(float cullDistance, float fadeOutRange); // 0x00637280-0x00637290
		public bool CellIsInRange(float cullDistance); // 0x00637290-0x006372A0
		public float MinDistanceToChangeLod(TerrainDetail detail); // 0x006372A0-0x00637370
		public bool GetLodRange(TerrainDetail detail, float cullDistance, out int minLod, out int maxLod); // 0x00637370-0x00637450
		public int SelectWithinRange(DetailLayer detailLayer, Vector3 cameraPosition, Vector3 terrainPosition, float minDistance, float maxDistance, List<InstanceBufferSlice> groups); // 0x00637450-0x00637A20
	}

	internal class CpuStream // TypeDefIndex: 2867
	{
		// Fields
		private readonly CpuCuller <Culler>k__BackingField; // 0x10
		private readonly RendererFactory _rendererFactory; // 0x18
		private readonly object _lock; // 0x20
		private readonly Dictionary<InstanceRenderer, List<InstanceBuffer>> _groups; // 0x28
		private List<InstanceBuffer> _slices; // 0x30
		private List<InstanceBufferSlice> _groupsToAdd; // 0x38

		// Properties
		public CpuCuller Culler { get; } // 0x00637A30-0x00637A40

		// Nested types
		internal struct RenderSettings // TypeDefIndex: 2868
		{
			// Fields
			public Vector3 TerrainPosition; // 0x00
			public Vector3 CameraPosition; // 0x0C
			public float CullDistance; // 0x18
		}

		// Constructors
		public CpuStream(CpuCuller culler, RendererFactory rendererFactory); // 0x00637A40-0x00637BF0

		// Methods
		public void Dispose(); // 0x00637BF0-0x00637E90
		public void RemoveDetailLayersFromRenderers(); // 0x00637E90-0x006380E0
		public void CopyDetailLayerToRenderer(Cell cell, DetailLayer detailLayer, RenderSettings data); // 0x006380E0-0x00638510
		private bool CopyLodToRenderer(DetailLayer detailLayer, int lod, CpuCuller culler, ref RenderSettings data); // 0x00638510-0x006387E0
		private void CopyInstancesToRenderer(DetailLayer detailLayer, TerrainDetail.LodGroup lod, InstanceBufferSlice group); // 0x006387E0-0x00638AB0
	}

	internal class DetailLayer // TypeDefIndex: 2869
	{
		// Fields
		private const int _BATCH_SIZE = 1023; // Metadata: 0x0015AC96
		private Tile[,] <Tiles>k__BackingField; // 0x10
		private TerrainDetail <Detail>k__BackingField; // 0x18
		private float <SqrDeltaDistanceThreshold>k__BackingField; // 0x20
		private Vector3 <PositionOfLastFlush>k__BackingField; // 0x24
		private readonly Cell _cell; // 0x30
		private readonly int _tileCount; // 0x38
		private Matrix4x4[] _instances; // 0x40
		private Vector4[] _colors; // 0x48
		private int _instanceIndex; // 0x50
		private Dictionary<int, InstanceRenderer> _cachedRenderers; // 0x58
		private int _renderedTiles; // 0x60
		private int _gizmoRenderCall; // 0x64

		// Properties
		public Tile[,] Tiles { get; private set; } // 0x00639050-0x00639060 0x00639060-0x00639070
		public int InstanceCount { get; } // 0x00637A20-0x00637A30
		public Matrix4x4[] Instances { get; } // 0x00639070-0x00639080
		public Vector4[] Colors { get; } // 0x00639080-0x00639090
		public TerrainDetail Detail { get; private set; } // 0x00639090-0x006390A0 0x006390A0-0x006390B0
		public float SqrDeltaDistanceThreshold { get; set; } // 0x006390B0-0x006390C0 0x006390C0-0x006390D0
		public Vector3 PositionOfLastFlush { get; set; } // 0x006390D0-0x006390E0 0x006390E0-0x006390F0
		public int Capacity { get; } // 0x006390F0-0x00639110
		public long Memory { get; } // 0x00639110-0x00639140

		// Nested types
		internal struct Tile // TypeDefIndex: 2870
		{
			// Fields
			public int X; // 0x00
			public int Z; // 0x04
			public bool HasInstances; // 0x08
			public Bounds LocalBounds; // 0x0C
			public Bounds WorldBounds; // 0x24
			public Matrix4x4[] Instances; // 0x40
			public Vector4[] Colors; // 0x48
			public int InstanceCount; // 0x50
		}

		// Constructors
		public DetailLayer(TerrainDetail detail, Cell cell); // 0x00635000-0x006350A0

		// Methods
		public void OnDrawGizmos(); // 0x00634CE0-0x00634ED0
		public void UpdateReference(TerrainDetail detail); // 0x00634FF0-0x00635000
		public void Dispose(); // 0x00634FE0-0x00634FF0
		public void AddInstance(Matrix4x4 matrix, Vector3 samplePosition); // 0x00627620-0x00628450
		public void PostBuild(); // 0x006267E0-0x00626B40
		private Vector4 CalculateColor(Vector3 position); // 0x00628450-0x006289E0
	}

	public class DetailRenderer : IDisposable // TypeDefIndex: 2871
	{
		// Fields
		private static object _sharedLock; // 0x00
		private EventHandler<DetailRenderer> Disposed; // 0x10
		public readonly Camera Camera; // 0x18
		internal readonly int CameraId; // 0x20
		private Camera <ReferenceCamera>k__BackingField; // 0x28
		public readonly RendererFactory RendererFactory; // 0x30
		private bool <VisibleCellsChanged>k__BackingField; // 0x38
		private Dictionary<int, InstanceRenderer> <Renderers>k__BackingField; // 0x40
		private RenderDiagnostics <Diagnostics>k__BackingField; // 0x48
		private int <ThreadCount>k__BackingField; // 0x80
		private readonly Grid _grid; // 0x88
		private Vector3 _cameraPosition; // 0x90
		private Vector3 _terrainPosition; // 0x9C
		private float _cullDistance; // 0xA8
		private FrustumCuller _frustumCuller; // 0xB0
		private Plane[] _frustumPlanes; // 0xB8
		private Dictionary<Cell, CpuStream> _cachedStreams; // 0xC0
		private Stopwatch _renderTimer; // 0xC8
		private int _culledCellInstances; // 0xD0
		private int _outOfRangeInstances; // 0xD4
		private int _builtCells; // 0xD8
		private long _memoryUsage; // 0xE0
		private RenderThread[] _renderThreads; // 0xE8
		private RenderThreadSyncer _syncer; // 0xF0
		private CancellationTokenSource _cancellationTokenSource; // 0xF8
		private RenderThread.ThreadInfo _mnainThread; // 0x100
		private bool _isStarted; // 0x108

		// Properties
		public Camera ReferenceCamera { get; set; } // 0x00639140-0x00639150 0x00639150-0x00639160
		public bool VisibleCellsChanged { get; private set; } // 0x00639160-0x00639170 0x00639170-0x00639180
		public Dictionary<int, InstanceRenderer> Renderers { get; private set; } // 0x00639180-0x00639190 0x00639190-0x006391A0
		private RenderDiagnostics Diagnostics { set; } // 0x006391A0-0x006391D0
		public int ThreadCount { get; private set; } // 0x006391D0-0x006391E0 0x006391E0-0x006391F0

		// Constructors
		public DetailRenderer(Camera camera, Grid grid, bool isScriptableRenderPipeline); // 0x006391F0-0x00639410
		static DetailRenderer(); // 0x0063EDA0-0x0063EDE0

		// Methods
		public void Start(int threadCount); // 0x00639560-0x00639BC0
		public void Dispose(); // 0x0063A2E0-0x0063A6D0
		public bool Render(bool useCache, bool allowPartialRender); // 0x0063A6D0-0x0063ADE0
		public void PrepareNextFrame(RenderSettings settings, bool async = true /* Metadata: 0x0015AC9A */); // 0x0063B2D0-0x0063B970
		protected void OnCalculateDiagnostics(RenderThread.ThreadInfo thread, RenderThreadSyncer syncer); // 0x0063C230-0x0063C5C0
		protected bool OnCullCells(RenderThread.ThreadInfo thread, RenderThreadSyncer syncer); // 0x0063C650-0x0063C8B0
		protected void OnBeginBatch(RenderThread.ThreadInfo thread, RenderThreadSyncer syncer); // 0x0063DA30-0x0063DA40
		protected void OnCopyDetailLayersToRenderers(RenderThread.ThreadInfo thread, RenderThreadSyncer syncer); // 0x0063DA40-0x0063E140
		protected void OnFinalize(RenderThread.ThreadInfo thread, RenderThreadSyncer syncer); // 0x0063E830-0x0063E9F0
		private void RemoveDetailLayersFromRenderers(RenderThread.ThreadInfo thread, Cell cell); // 0x0063E6E0-0x0063E780
		private void AddDetailLayersToRenderers(RenderThread.ThreadInfo thread, Cell cell); // 0x0063E330-0x0063E640
		private bool CellIsHiddenOrDirty(Cell cell); // 0x0063E640-0x0063E6E0
		private bool CellIsVisibleOrDirty(Cell cell); // 0x0063E780-0x0063E830
		private void AddCellToRenderers(RenderThread.ThreadInfo thread, Cell cell); // 0x0063E140-0x0063E330
		private bool LayerIsCulled(Camera camera, int layer); // 0x0063B1E0-0x0063B280
		private bool InstancingEnabled(Material[] materials); // 0x0063B030-0x0063B1E0
		private double MaxFillTime(RenderThread[] array); // 0x0063B280-0x0063B2D0
		private void CullCell(RenderThread.ThreadInfo thread, Cell cell, Vector3 cameraPosition, ref bool visibleCellsChanged, FrustumCuller frustumCuller); // 0x0063C8B0-0x0063D090
		private CpuCuller GetCellCuller(Cell cell); // 0x0063EC00-0x0063ECA0
		private void CheckMovementThresholds(Cell cell, Vector3 cameraPosition, CpuCuller cpuCuller, ref bool visibleCellsChanged); // 0x0063D4F0-0x0063D720
		private void OnCellLodChanged(Cell cell, ref bool visibleCellsChanged); // 0x0063ECA0-0x0063ED10
		private void SetCellVisibleOrChanged(Cell cell, ref bool visibleCellsChanged); // 0x0063D400-0x0063D4F0
		private void SetCellInvisible(Cell cell, ref bool visibleCellsChanged); // 0x0063D090-0x0063D180
		private void OnCellVisibilityChanged(Cell cell, Cell.VisibilityState state, ref bool visibleCellsChanged); // 0x0063ED20-0x0063EDA0
		private bool DistanceCull(Cell cell, Vector3 cameraPosition, float cullDistance); // 0x0063E9F0-0x0063EC00
		private bool FrustumCull(Cell cell, Vector3 position, FrustumCuller frustumCuller); // 0x0063D180-0x0063D400
		private void <PrepareNextFrame>b__49_0(); // 0x0063EDE0-0x0063EE20
	}

	public class Grid // TypeDefIndex: 2872
	{
		// Fields
		private Action<TerrainChangedFlags> WillBuild; // 0x10
		public readonly Terrain Terrain; // 0x18
		private bool <IsBuiltOrBuilding>k__BackingField; // 0x20
		private bool <IsBuilding>k__BackingField; // 0x21
		private TerrainChangedFlags <CurrentBuildFlags>k__BackingField; // 0x24
		private CachedTerrainData <TerrainData>k__BackingField; // 0x28
		private Cell[,] <Cells>k__BackingField; // 0x30
		private readonly float _cellSize; // 0x38
		private Camera _camera; // 0x40
		private Vector3 _cameraPosition; // 0x48
		private BuildQueue _buildQueue; // 0x58

		// Properties
		internal bool IsBuiltOrBuilding { get; private set; } // 0x0063EF40-0x0063EF50 0x0063EF50-0x0063EF60
		internal bool IsBuilding { get; private set; } // 0x0063EF60-0x0063EF70 0x0063EF70-0x0063EF80
		private TerrainChangedFlags CurrentBuildFlags { set; } // 0x0063EF80-0x0063EF90
		internal CachedTerrainData TerrainData { get; private set; } // 0x0063EF90-0x0063EFA0 0x0063EFA0-0x0063EFB0
		internal Bounds Bounds { get; } // 0x0063EFB0-0x0063EFE0
		public Cell[,] Cells { get; private set; } // 0x0063EFE0-0x0063EFF0 0x0063EFF0-0x0063F000
		internal float CellSize { get; } // 0x0063F000-0x0063F010
		internal float TileSize { get; } // 0x0063ED10-0x0063ED20

		// Events
		public event Action<TerrainChangedFlags> WillBuild {{
			add; // 0x0063EE20-0x0063EEB0
			remove; // 0x0063EEB0-0x0063EF40
		}

		// Nested types
		private sealed class <>c__DisplayClass51_0 // TypeDefIndex: 2873
		{
			// Fields
			public Grid <>4__this; // 0x10
			public CachedTerrainData terrainDataCopy; // 0x18
			public TerrainChangedFlags flags; // 0x20
			public CellStreamer.StreamSettings streamInfo; // 0x24
			public Camera priorityCamera; // 0x40

			// Constructors
			public <>c__DisplayClass51_0(); // 0x00B0A980-0x00B0A990

			// Methods
			internal void <RebuildCells>b__0(object obj); // 0x00B0A990-0x00B0ABD0
		}

		// Constructors
		public Grid(Terrain terrain, float cellSize); // 0x0063F010-0x0063F020

		// Methods
		public void Dispose(); // 0x0063F020-0x0063F5B0
		public void RefreshPrototypes(Camera camera, Material billboardMaterial, out bool requiresRebuild); // 0x0063F5B0-0x0063F5E0
		public void Initialize(Material billboardMaterial); // 0x0063F5E0-0x0063F720
		internal void Build(Cell[] cells, int count, CachedTerrainData terrainData, CellStreamer.StreamSettings streamInfo); // 0x00636D30-0x00637000
		public void Rebuild(TerrainChangedFlags flags, Camera priorityCamera, Material billboardMaterial, CellStreamer.StreamSettings streamInfo); // 0x0063FE40-0x0063FFC0
		public void WaitUntilBuildFinished(); // 0x00640550-0x006405B0
		public void Clear(); // 0x006403A0-0x00640550
		private void OnBuildFinished(); // 0x006405B0-0x006405C0
		private void CacheTerrainData(Material billboardMaterial, out bool flushEverything); // 0x0063F720-0x0063F8B0
		private PooledList<BuildQueue.CellBuildData> GetCellsInRect(Rect rect, bool[] dirtyLayers, TerrainChangedFlags flags, CachedTerrainData terrainData); // 0x006405C0-0x00640940
		private void ValidateCells(CachedTerrainData terrainData, float cellSize); // 0x0063F8B0-0x0063FE40
		private void PushAllCellsToBuildQueue(CachedTerrainData terrainData, CellStreamer.StreamSettings streamInfo); // 0x00640940-0x00640FC0
		private void PushModifiedCellsToBuildQueue(CachedTerrainData terrainData, TerrainChangedFlags flags, bool[] dirtyLayers, CellStreamer.StreamSettings streamInfo); // 0x00640FC0-0x00641310
		private bool[] GetDirtyLayers(CachedTerrainData terrainData, TerrainChangedFlags flags); // 0x00641310-0x00641490
		private void RebuildCells(float size, TerrainChangedFlags flags, CachedTerrainData terrainData, Camera priorityCamera, CellStreamer.StreamSettings streamInfo); // 0x0063FFC0-0x006403A0
	}

	public class MeshGenerator : IDisposable // TypeDefIndex: 2874
	{
		// Fields
		private List<UnityEngine.Object> _managedResources; // 0x10

		// Constructors
		public MeshGenerator(); // 0x00641490-0x006414E0

		// Methods
		public void Dispose(); // 0x00632A90-0x00632CA0
		public GameObject CreateGrassMesh(Material material); // 0x0062E7D0-0x0062F3E0
		public Material CreateGrassMaterial(Texture2D texture, Material sourceMaterial); // 0x0062E3B0-0x0062E7D0
		private void SetupMaterialKeywordsAndPass(Material material); // 0x00631670-0x006320F0
		private void FixMaskMap(Material material); // 0x00631530-0x00631670
		private Texture2D FixGrayscaleTexture(Texture2D texture); // 0x006320F0-0x00632600
		private Texture CreateDefaultMaskMap(); // 0x00632900-0x00632A90
		private Color CalculateMainColorFromTex(Texture2D texture); // 0x00632600-0x00632900
	}

	[DisallowMultipleComponent] // 0x00254B10-0x00254B30
	[ExecuteInEditMode] // 0x00254B10-0x00254B30
	public class NatureRenderer : MonoBehaviour // TypeDefIndex: 2875
	{
		// Fields
		private static MethodInfo _isInPrefabMode; // 0x00
		private static readonly List<NatureRenderer> _renderers; // 0x08
		private EventHandler<DetailRenderer> PreRender; // 0x18
		private EventHandler<DetailRenderer> PostRender; // 0x20
		private EventHandler<DetailRenderer> RendererCreated; // 0x28
		private Camera <PriorityCamera>k__BackingField; // 0x30
		private Camera <ReferenceCamera>k__BackingField; // 0x38
		private bool _allowPartialRender; // 0x40
		[SerializeField] // 0x00254B50-0x00254B60
		private float _renderProcessorLimit; // 0x44
		[SerializeField] // 0x00254B60-0x00254B70
		private bool _stream; // 0x48
		[SerializeField] // 0x00254B70-0x00254B80
		private float _streamProcessorLimit; // 0x4C
		[SerializeField] // 0x00254B80-0x00254B90
		private float _streamInDistance; // 0x50
		[SerializeField] // 0x00254B90-0x00254BA0
		private float _streamOutDistance; // 0x54
		[SerializeField] // 0x00254BA0-0x00254BB0
		private float _detailDistance; // 0x58
		[SerializeField] // 0x00254BB0-0x00254BC0
		private Material _billboardGrassMaterial; // 0x60
		[SerializeField] // 0x00254BC0-0x00254BD0
		private float _cellSize; // 0x68
		[SerializeField] // 0x00254BD0-0x00254BE0
		private bool _drawCells; // 0x6C
		private Terrain _unityTerrain; // 0x70
		private int _isDirty; // 0x78
		private int _heightIsDirty; // 0x7C
		private int _flushAll; // 0x80
		private Grid _grid; // 0x88
		private bool _isRendered; // 0x90
		private Dictionary<Camera, DetailRenderer> _renderersPerCamera; // 0x98
		private Plane[] _frustumPlanes; // 0xA0
		private NatureRendererGizmos _gizmos; // 0xA8
		private int _rebuildInterval; // 0xB0
		private bool _isVisible; // 0xB4
		private CellStreamer _streamer; // 0xB8
		private Type <RenderPipelineManager>k__BackingField; // 0xC0

		// Properties
		public static IEnumerable<NatureRenderer> Renderers { get; } // 0x006414E0-0x00641530
		public DetailRenderer[] DetailRenderers { get; } // 0x00641890-0x00641930
		public float DetailDistance { get; set; } // 0x00641930-0x00641940 0x00641940-0x00641950
		public Camera PriorityCamera { get; set; } // 0x00641950-0x00641960 0x00641960-0x00641970
		public Camera ReferenceCamera { get; set; } // 0x00641970-0x00641980 0x00641980-0x00641990
		public Material BillboardGrassMaterial { get; set; } // 0x00641990-0x006419A0 0x006419A0-0x006419B0
		public DetailRenderer this[Camera camera] { get => default; } // 0x006419B0-0x00641B10
		public CachedTerrainData TerrainData { get; } // 0x00641B10-0x00641B30
		public Grid Grid { get; } // 0x00641B30-0x00641B40
		protected Type RenderPipelineManager { get; private set; } // 0x00645130-0x00645140 0x00645140-0x00645150

		// Events
		public event EventHandler<DetailRenderer> PreRender {{
			add; // 0x00641530-0x006415C0
			remove; // 0x006415C0-0x00641650
		}
		public event EventHandler<DetailRenderer> PostRender {{
			add; // 0x00641650-0x006416E0
			remove; // 0x006416E0-0x00641770
		}
		public event EventHandler<DetailRenderer> RendererCreated {{
			add; // 0x00641770-0x00641800
			remove; // 0x00641800-0x00641890
		}

		// Constructors
		public NatureRenderer(); // 0x00645150-0x00645250
		static NatureRenderer(); // 0x00645250-0x006452A0

		// Methods
		public float GetVisibleCellBuildProgress(); // 0x00641B40-0x00641B70
		public void FlushMaterials(); // 0x00641B70-0x00641E00
		public void RebuildBuffersDelayed(); // 0x00641EC0-0x00641EE0
		public void RebuildBuffers(TerrainChangedFlags flags); // 0x00641EE0-0x00642360
		private void OnEnable(); // 0x00642360-0x00642430
		private void Subscribe(); // 0x00642760-0x00642860
		private void Unsubscribe(); // 0x006429F0-0x00642A90
		private void RenderPipelineManager_beginCameraRendering(object context, Camera camera); // 0x00642A90-0x00642AA0
		private void OnDisable(); // 0x00643C90-0x00643F30
		private void Awake(); // 0x00644030-0x00644090
		private void Start(); // 0x00644090-0x00644240
		private void OnDestroy(); // 0x00644240-0x006442E0
		private void Dispose(); // 0x00643F30-0x00644030
		private void DisposeRenderers(); // 0x00643710-0x00643810
		private void Initialize(); // 0x00642430-0x00642760
		private void _terrainCells_OnWillBuild(TerrainChangedFlags flags); // 0x00644340-0x00644350
		private void OnCameraRender(Camera camera); // 0x00642AA0-0x00642C80
		private void OnTerrainChanged(TerrainChangedFlags flags); // 0x00644350-0x00644390
		private void OnDrawGizmos(); // 0x00644390-0x00644500
		private bool TerrainIsInRange(Camera camera); // 0x00643810-0x00643BA0
		public void Stream(Camera camera); // 0x00643BA0-0x00643C90
		public void Render(Camera camera); // 0x00642C80-0x00643710
		private Type FindType(string fullname); // 0x00642860-0x006429F0
		private void SetupHdrp(); // 0x006442E0-0x00644320
	}

	internal class NatureRendererGizmos // TypeDefIndex: 2876
	{
		// Fields
		private readonly NatureRenderer _renderer; // 0x10
		private readonly Grid _terrainCells; // 0x18
		private readonly Dictionary<Camera, DetailRenderer> _cameras; // 0x20
		private readonly Terrain _unityTerrain; // 0x28

		// Nested types
		[Serializable]
		private sealed class <>c // TypeDefIndex: 2877
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static Func<Camera, bool> <>9__5_0; // 0x08

			// Constructors
			static <>c(); // 0x00B0ABD0-0x00B0AC10
			public <>c(); // 0x00B0AC10-0x00B0AC20

			// Methods
			internal bool <DrawCells>b__5_0(Camera c); // 0x00B0AC20-0x00B0AD00
		}

		// Constructors
		public NatureRendererGizmos(Terrain terrain, NatureRenderer renderer, Grid buffer, Dictionary<Camera, DetailRenderer> cameras); // 0x00644320-0x00644340

		// Methods
		public void DrawCells(bool isInRange); // 0x00644500-0x00645130
	}

	internal class PlacementAlgorithm // TypeDefIndex: 2878
	{
		// Fields
		public readonly CachedTerrainData TerrainData; // 0x10
		private Vector2 _areaSize; // 0x18
		private Vector2 _divideByTerrainSize; // 0x20
		private System.Random _random; // 0x28
		private static float[] _randomCache; // 0x00

		// Constructors
		public PlacementAlgorithm(CachedTerrainData terrainData); // 0x00634650-0x00634700
		static PlacementAlgorithm(); // 0x006452A0-0x006452F0

		// Methods
		public Matrix4x4 Place(TerrainDetail detail, Vector3 position, Vector3 terrainPosition, int seed); // 0x00626B40-0x00627620
	}

	public struct RenderDiagnostics // TypeDefIndex: 2879
	{
		// Fields
		public int Instances; // 0x00
		public int Batches; // 0x04
		public int Culled; // 0x08
		public int CulledCells; // 0x0C
		public int BuiltCells; // 0x10
		public int OutOfRangeCells; // 0x14
		public int RenderersCpu; // 0x18
		public int RenderersGpu; // 0x1C
		public double FillTime; // 0x20
		public double RenderTime; // 0x28
		public long Memory; // 0x30
	}

	public class RendererFactory // TypeDefIndex: 2880
	{
		// Fields
		private EventHandler<InstanceRenderer> RendererCreated; // 0x10
		private readonly Dictionary<int, InstanceRenderer> _rendererCollection; // 0x18
		private readonly bool _isScriptableRenderPipeline; // 0x20
		private readonly bool _supportsComputeShaders; // 0x21
		private readonly object _lockObject; // 0x28

		// Constructors
		public RendererFactory(Dictionary<int, InstanceRenderer> renderers, bool isScriptableRenderPipeline, object lockObject); // 0x00639490-0x00639560

		// Methods
		public InstanceRenderer GetRenderer(TerrainDetail.LodGroup lodGroup, bool useComputeShaders); // 0x00638AB0-0x00639050
	}

	public struct RenderSettings // TypeDefIndex: 2881
	{
		// Fields
		public float DetailDistance; // 0x00

		// Constructors
		public RenderSettings(float detailDistance); // 0x002658D0-0x002658E0
	}

	public class RenderThread // TypeDefIndex: 2882
	{
		// Fields
		private static object _sharedLock; // 0x00
		private static bool _visibleCellsChanged; // 0x08
		private Action<ThreadInfo, RenderThreadSyncer> CalculateDiagnostics; // 0x10
		private Func<ThreadInfo, RenderThreadSyncer, bool> CullCells; // 0x18
		private Action<ThreadInfo, RenderThreadSyncer> BeginBatch; // 0x20
		private Action<ThreadInfo, RenderThreadSyncer> CopyDetailLayersToRenderers; // 0x28
		private Action<ThreadInfo, RenderThreadSyncer> Finalize; // 0x30
		private ThreadInfo <Thread>k__BackingField; // 0x38
		private long <ElapsedMilliseconds>k__BackingField; // 0x40
		private readonly Stopwatch _fillTimer; // 0x48
		private readonly Stopwatch _renderTimer; // 0x50
		private readonly FrustumCuller _culler; // 0x58
		private readonly RenderThreadSyncer _syncer; // 0x60
		private bool _doNextLoop; // 0x68

		// Properties
		public bool DoNextLoop { set; } // 0x006455C0-0x006455D0
		public ThreadInfo Thread { get; private set; } // 0x006455D0-0x006455E0 0x006455E0-0x006455F0
		public long ElapsedMilliseconds { get; private set; } // 0x006455F0-0x00645600 0x00645600-0x00645610

		// Events
		public event Action<ThreadInfo, RenderThreadSyncer> CalculateDiagnostics {{
			add; // 0x0063A010-0x0063A0A0
			remove; // 0x006452F0-0x00645380
		}
		public event Func<ThreadInfo, RenderThreadSyncer, bool> CullCells {{
			add; // 0x0063A0A0-0x0063A130
			remove; // 0x00645380-0x00645410
		}
		public event Action<ThreadInfo, RenderThreadSyncer> BeginBatch {{
			add; // 0x0063A130-0x0063A1C0
			remove; // 0x00645410-0x006454A0
		}
		public event Action<ThreadInfo, RenderThreadSyncer> CopyDetailLayersToRenderers {{
			add; // 0x0063A1C0-0x0063A250
			remove; // 0x006454A0-0x00645530
		}
		public event Action<ThreadInfo, RenderThreadSyncer> Finalize {{
			add; // 0x0063A250-0x0063A2E0
			remove; // 0x00645530-0x006455C0
		}

		// Nested types
		public class ThreadInfo // TypeDefIndex: 2883
		{
			// Fields
			public int ThreadNumber; // 0x10
			public int ThreadCount; // 0x14
			public CancellationToken CancellationToken; // 0x18
			public Stopwatch Timer; // 0x20
			public Thread Thread; // 0x28
			public int LoopIndex; // 0x30

			// Constructors
			public ThreadInfo(); // 0x00B0AD00-0x00B0AD10
		}

		// Constructors
		public RenderThread(RenderThreadSyncer syncer, ThreadInfo threadInfo); // 0x00639C50-0x00639ED0
		static RenderThread(); // 0x00645CD0-0x00645D20

		// Methods
		public void Start(int threadNumber, int threadCount, CancellationToken cancellationToken); // 0x00639ED0-0x0063A010
		public void Render(bool async); // 0x0063BC40-0x0063C120
		private void OnDomainUnload(object sender, EventArgs e); // 0x00645650-0x00645830
		private void RenderLoop(object arg); // 0x00645830-0x00645A20
	}

	public class RenderThreadSyncer // TypeDefIndex: 2884
	{
		// Fields
		private readonly Task[] _tasks; // 0x10
		private readonly object _lock; // 0x18
		private Barrier _barrier; // 0x20
		private int[] _parallelIndices; // 0x28

		// Nested types
		public enum Task // TypeDefIndex: 2885
		{
			None = 0,
			Diagnostics = 1,
			Cull = 2,
			EndCull = 3,
			Copy = 4,
			Done = 5
		}

		// Constructors
		public RenderThreadSyncer(int threadCount, int syncPoints, CancellationToken cancellationToken); // 0x00639BC0-0x00639C50

		// Methods
		public void BeginParallel(RenderThread.ThreadInfo thread); // 0x0063C5C0-0x0063C600
		public bool ParallelNext(RenderThread.ThreadInfo thread); // 0x0063C600-0x0063C650
		public void Lock(Action action); // 0x0063BAE0-0x0063BB90
		public bool WaitSelf(RenderThread.ThreadInfo thread, ref bool condition, CancellationToken cancellationToken); // 0x00645A20-0x00645CD0
		public void PulseAll(); // 0x0063BB90-0x0063BC40
		public void Pulse(RenderThread.ThreadInfo thread, Task task); // 0x0063C120-0x0063C230
		public void Sync(RenderThread.ThreadInfo thread, Task task, int syncPointNumber, CancellationToken cancellationToken, int timeout = 1500 /* Metadata: 0x0015AC9B */); // 0x00645610-0x00645650
		public bool Wait(RenderThread.ThreadInfo thread, Task task, int timeout = 1500 /* Metadata: 0x0015AC9F */); // 0x0063ADE0-0x0063B030
		private bool IsTrue(Task task, RenderThread.ThreadInfo currentThread); // 0x00645D20-0x00645DC0
		public override string ToString(); // 0x00645DC0-0x00646040
	}

	public class TerrainDetail // TypeDefIndex: 2886
	{
		// Fields
		private string <Name>k__BackingField; // 0x10
		private Exception <Exception>k__BackingField; // 0x18
		private ErrorCode <Error>k__BackingField; // 0x20
		private bool <IsValid>k__BackingField; // 0x24
		public readonly int Index; // 0x28
		private float <MinHeight>k__BackingField; // 0x2C
		private float <MaxHeight>k__BackingField; // 0x30
		private float <MinWidth>k__BackingField; // 0x34
		private float <MaxWidth>k__BackingField; // 0x38
		private float <NoiseSpread>k__BackingField; // 0x3C
		private bool <HasColor>k__BackingField; // 0x40
		private Color <DryColor>k__BackingField; // 0x44
		private Color <HealthyColor>k__BackingField; // 0x54
		private Color[] <MainColors>k__BackingField; // 0x68
		private bool <SupportsIndirectInstancing>k__BackingField; // 0x70
		private bool <HasLoD>k__BackingField; // 0x71
		private LodGroup[] <LodGroups>k__BackingField; // 0x78
		private Quaternion <Orientation>k__BackingField; // 0x80
		private Vector3 <Offset>k__BackingField; // 0x90
		private readonly CachedTerrainData _terrainData; // 0xA0
		private MeshRenderer _cachedMeshRenderer; // 0xA8
		private GameObject _cachedPrototype; // 0xB0
		private LODGroup _cachedLodGroup; // 0xB8
		private MeshFilter[] _cachedLodMeshFilters; // 0xC0
		private Texture[] _cachedMainTextures; // 0xC8
		private GameObject _texturePrototype; // 0xD0
		private Material _material; // 0xD8
		private Material _cachedBillboardMaterial; // 0xE0
		private MeshGenerator _meshGenerator; // 0xE8
		private float? _previousFieldOfView; // 0xF0

		// Properties
		private string Name { set; } // 0x00646040-0x00646050
		private Exception Exception { set; } // 0x00646050-0x00646060
		private ErrorCode Error { set; } // 0x00646060-0x00646070
		public bool IsValid { get; private set; } // 0x00646070-0x00646080 0x00646080-0x00646090
		public float MinHeight { get; private set; } // 0x00646090-0x006460A0 0x006460A0-0x006460B0
		public float MaxHeight { get; private set; } // 0x006460B0-0x006460C0 0x006460C0-0x006460D0
		public float MinWidth { get; private set; } // 0x006460D0-0x006460E0 0x006460E0-0x006460F0
		public float MaxWidth { get; private set; } // 0x006460F0-0x00646100 0x00646100-0x00646110
		public float NoiseSpread { get; private set; } // 0x00646110-0x00646120 0x00646120-0x00646130
		public bool HasColor { get; private set; } // 0x00646130-0x00646140 0x00646140-0x00646150
		public Color DryColor { get; private set; } // 0x00646150-0x00646160 0x00646160-0x00646170
		public Color HealthyColor { get; private set; } // 0x00646170-0x00646180 0x00646180-0x00646190
		public Color[] MainColors { get; private set; } // 0x00646190-0x006461A0 0x006461A0-0x006461B0
		public bool SupportsIndirectInstancing { get; private set; } // 0x006461B0-0x006461C0 0x006461C0-0x006461D0
		public bool HasLoD { get; private set; } // 0x006461D0-0x006461E0 0x006461E0-0x006461F0
		public LodGroup[] LodGroups { get; private set; } // 0x006461F0-0x00646200 0x00646200-0x00646210
		public Quaternion Orientation { get; private set; } // 0x00646210-0x00646230 0x00646230-0x00646240
		public Vector3 Offset { get; private set; } // 0x00646240-0x00646260 0x00646260-0x00646270

		// Nested types
		public enum ErrorCode // TypeDefIndex: 2887
		{
			PrototypeIsNull = 0,
			MeshRendererIsNull = 1,
			MeshFilterIsNull = 2,
			MeshIsNull = 3,
			Exception = 4
		}

		public struct LodGroup // TypeDefIndex: 2888
		{
			// Fields
			public readonly int InstanceId; // 0x00
			public readonly Mesh Mesh; // 0x08
			public readonly Material[] Materials; // 0x10
			public readonly Material[] SharedMaterials; // 0x18
			public readonly float CullDistance; // 0x20
			public readonly float SqrCullDistance; // 0x24
			public readonly ShadowCastingMode ShadowCasting; // 0x28
			public readonly bool ReceiveShadow; // 0x2C
			public readonly Bounds Bounds; // 0x30
			public readonly LODFadeMode FadeMode; // 0x48
			public readonly float ScreenRelativeTransitionHeight; // 0x4C
			public readonly InstanceData.ColorType Coloring; // 0x50
			public readonly int Layer; // 0x54
			public readonly bool IsLastLod; // 0x58
			public readonly bool LightProbes; // 0x59
			public readonly bool OcclusionProbes; // 0x5A

			// Constructors
			public LodGroup(GameObject prototype, Mesh mesh, Material[] materials, Material[] sharedMaterials, Bounds bounds, float distance, ShadowCastingMode shadowCasting, bool receiveShadows, LODFadeMode fadeMode, float screenRelativeTransitionHeight, InstanceData.ColorType coloring, int layer, bool isLastLod, bool lightProbes, bool occlusionProbes); // 0x00287A30-0x00287B40

			// Methods
			public static explicit operator InstanceData(LodGroup detail); // 0x00B0AE40-0x00B0B220
		}

		[Serializable]
		private sealed class <>c // TypeDefIndex: 2889
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static Func<Material, bool> <>9__91_0; // 0x08

			// Constructors
			static <>c(); // 0x00B0AD10-0x00B0AD50
			public <>c(); // 0x00B0AD50-0x00B0AD60

			// Methods
			internal bool <CopyLevel>b__91_0(Material m); // 0x00B0AD60-0x00B0AE40
		}

		// Constructors
		public TerrainDetail(CachedTerrainData terrainData, DetailPrototype detail, int layer, float fieldOfView, Material billboardMaterial); // 0x00632F50-0x00632F80

		// Methods
		public void Dispose(); // 0x0062A520-0x0062A750
		public void FlushMaterials(DetailPrototype detail, Material billboardMaterial); // 0x00641E00-0x00641EC0
		public void CopyFrom(DetailPrototype detail, float fieldOfView, out bool flushEverything, Material billboardMaterial); // 0x0062A750-0x0062DB20
		private bool MaterialSupportsIndirectInstancing(); // 0x00630D60-0x00630EA0
		private bool MaterialSupportsIndirectInstancing(Material material); // 0x00646310-0x00646540
		private bool CopyLevel(int i, MeshRenderer renderer, GameObject prototype, float lodDistance, float transitionHeight, float fieldOfView, LODFadeMode fadeMode, bool isLastLod); // 0x0062F3E0-0x00630BF0
		private bool MaterialsChanged(LodGroup level, MeshRenderer renderer); // 0x006311A0-0x006313D0
		private bool ShaderChanged(Material a, Material b); // 0x0062DE40-0x0062E0C0
		private InstanceData.ColorType GetColorMethod(Material material); // 0x006313D0-0x00631530
		private float RelativeHeightToDistance(float relativeHeight, float size, float fieldOfView); // 0x00646270-0x00646310
		private Color CalculateMainColorFromTex(int materialIndex); // 0x00630BF0-0x00630D60
		private Color CalculateMainColorFromTex(Texture2D texture); // 0x00630EA0-0x006311A0
		private Texture GetMainTexture(Material material); // 0x0062E0C0-0x0062E3B0
	}
}

namespace VisualDesignCafe.Nature
{
	[ExecuteAlways] // 0x00254BE0-0x00254BF0
	public class GlobalWind : MonoBehaviour // TypeDefIndex: 2891
	{
		// Fields
		[SerializeField] // 0x00254BF0-0x00254C00
		private WindSettings _windSettings; // 0x18
		[SerializeField] // 0x00254C00-0x00254C10
		private WindZone _sourceWindZone; // 0x30
		[SerializeField] // 0x00254C10-0x00254C20
		private Texture2D _gustNoise; // 0x38
		[SerializeField] // 0x00254C20-0x00254C30
		private Texture2D _shiverNoise; // 0x40
		[SerializeField] // 0x00254C30-0x00254C40
		private int _selectedPreset; // 0x48
		private Quaternion _cachedRotation; // 0x4C
		private float _cachedWindMain; // 0x5C
		private float _cachedWindPulseFrequency; // 0x60
		private float _cachedWindTurbulence; // 0x64

		// Properties
		public WindSettings Settings { get; set; } // 0x00B163E0-0x00B16400 0x00B16400-0x00B164B0
		public WindZone Zone { get; set; } // 0x00B164B0-0x00B164C0 0x00B164C0-0x00B165F0
		public Texture2D GustNoise { get; set; } // 0x00B16BE0-0x00B16BF0 0x00B16BF0-0x00B16CD0
		public Texture2D ShiverNoise { get; set; } // 0x00B16CD0-0x00B16CE0 0x00B16CE0-0x00B16D50

		// Constructors
		public GlobalWind(); // 0x00B17320-0x00B17380

		// Methods
		private void OnEnable(); // 0x00B16D50-0x00B16ED0
		private void Update(); // 0x00B16F10-0x00B17040
		private void CopyAndApply(); // 0x00B16BA0-0x00B16BE0
		private void CopyFromWindZone(); // 0x00B16ED0-0x00B16F10
		private bool WindZoneHasChanged(); // 0x00B17040-0x00B17320
		private void CacheWindZoneProperties(); // 0x00B167A0-0x00B16930
		private void ValidateWindZone(); // 0x00B165F0-0x00B167A0
	}

	internal class RuntimeGlobalWindInitializer // TypeDefIndex: 2892
	{
		// Nested types
		[Serializable]
		private sealed class <>c // TypeDefIndex: 2893
		{
			// Fields
			public static readonly <>c <>9; // 0x00
			public static Func<GameObject, bool> <>9__1_0; // 0x08

			// Constructors
			static <>c(); // 0x00B17790-0x00B177D0
			public <>c(); // 0x00B177D0-0x00B177E0

			// Methods
			internal bool <OnActiveSceneChanged>b__1_0(GameObject g); // 0x00B177E0-0x00B178F0
		}

		// Constructors
		public RuntimeGlobalWindInitializer(); // 0x00B176D0-0x00B176E0

		// Methods
		[RuntimeInitializeOnLoadMethod] // 0x00254C40-0x00254C50
		private static void Initialize(); // 0x00B173A0-0x00B174E0
		private static void OnActiveSceneChanged(Scene previousScene, Scene activeScene); // 0x00B174E0-0x00B176A0
		private static void ApplyDefaultWind(); // 0x00B176A0-0x00B176D0
	}

	[Serializable]
	public struct WindSettings // TypeDefIndex: 2894
	{
		// Fields
		public Vector2 GustDirection; // 0x00
		public float GustStrength; // 0x08
		public float GustSpeed; // 0x0C
		public float ShiverSpeed; // 0x10
		public float ShiverStrength; // 0x14

		// Properties
		public static WindSettings Calm { get; } // 0x00B17380-0x00B173A0

		// Methods
		public static WindSettings FromWindZone(WindZone windZone); // 0x00B16930-0x00B16BA0
		public static Vector2 RotationToDirection(Quaternion quaternion); // 0x00B176E0-0x00B17790
		public void Apply(Texture2D gustNoise, Texture2D shiverNoise); // 0x00288D80-0x00288DF0
		public void Apply(); // 0x00288DF0-0x00288E00
	}
}

public class BGMusic : MonoBehaviour // TypeDefIndex: 2896
{
	// Fields
	public float volume; // 0x18
	private AudioSource audioData; // 0x20
	private int awoken; // 0x28

	// Constructors
	public BGMusic(); // 0x004078E0-0x00407920

	// Methods
	private void Start(); // 0x004073A0-0x004075A0
	private void Awake(); // 0x00407660-0x00407780
	public void pauseAudio(); // 0x00407780-0x00407830
	public void playAudio(); // 0x00407830-0x004078E0
	public void setAudioVolume(float volume); // 0x004075A0-0x00407660
}

public class Ladder : MonoBehaviour // TypeDefIndex: 2897
{
	// Fields
	[SerializeField] // 0x00254E60-0x00254E70
	private bool showGizmos; // 0x18
	[SerializeField] // 0x00254E70-0x00254E80
	private Transform topExit; // 0x20
	[SerializeField] // 0x00254E80-0x00254E90
	private Transform bottomExit; // 0x28
	[SerializeField] // 0x00254E90-0x00254EA0
	private int stepsNumber; // 0x30
	[SerializeField] // 0x00254EA0-0x00254EB0
	private Vector3 topLocalPosition; // 0x34
	[SerializeField] // 0x00254EB0-0x00254EC0
	private Vector3 bottomLocalPosition; // 0x40
	[SerializeField] // 0x00254EC0-0x00254ED0
	private FacingDirection facingDirection; // 0x4C
	private Vector3 facingDirectionVector; // 0x50
	private List<Vector3> steps; // 0x60

	// Properties
	public List<Vector3> Steps { get; } // 0x00369D30-0x00369D40
	public Transform TopExit { get; } // 0x00369D40-0x00369D50
	public Transform BottomExit { get; } // 0x00369D50-0x00369D60
	public Vector3 TopPosition { get; } // 0x00369D60-0x00369EA0
	public Vector3 BottomPosition { get; } // 0x00369EA0-0x00369FE0
	public Vector3 BottomToTop { get; } // 0x00369FE0-0x0036A290
	public Vector3 FacingDirectionVector { get; } // 0x0036A290-0x0036A2A0

	// Nested types
	private enum FacingDirection // TypeDefIndex: 2898
	{
		PositiveZ = 0,
		NegativeZ = 1,
		PositiveX = 2,
		NegativeX = 3
	}

	// Constructors
	public Ladder(); // 0x0036B4E0-0x0036B6A0

	// Methods
	public int GetClosestStepIndex(Vector3 referencePosition); // 0x0036A2A0-0x0036A3F0
	private void Awake(); // 0x0036A3F0-0x0036A800
	private void OnDrawGizmos(); // 0x0036A800-0x0036B4E0
}

public class CapsuleColliderComponent2D : ColliderComponent2D // TypeDefIndex: 2899
{
	// Fields
	private CapsuleCollider2D capsuleCollider; // 0x20

	// Properties
	public override Vector3 Size { get; set; } // 0x0040E4B0-0x0040E570 0x0040E570-0x0040E620
	public override Vector3 Offset { get; set; } // 0x0040E620-0x0040E6E0 0x0040E6E0-0x0040E790

	// Constructors
	public CapsuleColliderComponent2D(); // 0x0040E9A0-0x0040E9E0

	// Methods
	protected override void Awake(); // 0x0040E790-0x0040E810
}

public class CapsuleColliderComponent3D : ColliderComponent3D // TypeDefIndex: 2900
{
	// Fields
	private CapsuleCollider capsuleCollider; // 0x20

	// Properties
	public override Vector3 Size { get; set; } // 0x0040EA20-0x0040EB20 0x0040EB20-0x0040EBE0
	public override Vector3 Offset { get; set; } // 0x0040EBE0-0x0040EC60 0x0040EC60-0x0040ECD0

	// Constructors
	public CapsuleColliderComponent3D(); // 0x0040EF90-0x0040EFD0

	// Methods
	protected override void Awake(); // 0x0040ECD0-0x0040ED50
}

public abstract class ColliderComponent : MonoBehaviour // TypeDefIndex: 2901
{
	// Properties
	public abstract Vector3 Size { get; set; }
	public abstract Vector3 Offset { get; set; }

	// Constructors
	protected ColliderComponent(); // 0x00428B30-0x00428B70

	// Methods
	protected virtual void Awake(); // 0x00428AE0-0x00428B30
}

public abstract class ColliderComponent2D : ColliderComponent // TypeDefIndex: 2902
{
	// Fields
	protected Collider2D collider; // 0x18

	// Properties
	public PhysicsMaterial2D Material { get; set; } // 0x00428B70-0x00428BC0 0x00428BC0-0x00428C20

	// Constructors
	protected ColliderComponent2D(); // 0x0040E9E0-0x0040EA20

	// Methods
	protected override void Awake(); // 0x0040E810-0x0040E9A0
}

public abstract class ColliderComponent3D : ColliderComponent // TypeDefIndex: 2903
{
	// Fields
	protected Collider collider; // 0x18

	// Properties
	public PhysicMaterial Material { get; set; } // 0x00428C20-0x00428C70 0x00428C70-0x00428CD0

	// Constructors
	protected ColliderComponent3D(); // 0x0040EFD0-0x0040F010

	// Methods
	protected override void Awake(); // 0x0040ED50-0x0040EF90
}

public class SphereColliderComponent2D : ColliderComponent2D // TypeDefIndex: 2904
{
	// Fields
	private CircleCollider2D circleCollider; // 0x20

	// Properties
	public override Vector3 Size { get; set; } // 0x003CA9F0-0x003CAAF0 0x003CAAF0-0x003CAB60
	public override Vector3 Offset { get; set; } // 0x003CAB60-0x003CAC20 0x003CAC20-0x003CACD0

	// Constructors
	public SphereColliderComponent2D(); // 0x003CAD60-0x003CADA0

	// Methods
	protected override void Awake(); // 0x003CACD0-0x003CAD60
}

public class SphereColliderComponent3D : ColliderComponent3D // TypeDefIndex: 2905
{
	// Fields
	private SphereCollider sphereCollider; // 0x20

	// Properties
	public override Vector3 Size { get; set; } // 0x003CADA0-0x003CAEC0 0x003CAEC0-0x003CAF30
	public override Vector3 Offset { get; set; } // 0x003CAF30-0x003CAFB0 0x003CAFB0-0x003CB020

	// Constructors
	public SphereColliderComponent3D(); // 0x003CB0B0-0x003CB0F0

	// Methods
	protected override void Awake(); // 0x003CB020-0x003CB0B0
}

public class CheckLayer : MonoBehaviour // TypeDefIndex: 2906
{
	// Constructors
	public CheckLayer(); // 0x00428AA0-0x00428AE0
}

public class DisableOnLoad : MonoBehaviour // TypeDefIndex: 2907
{
	// Fields
	public bool stateOnLoad; // 0x18

	// Constructors
	public DisableOnLoad(); // 0x00359C40-0x00359C80

	// Methods
	private void Start(); // 0x00359BA0-0x00359C40
}

public class Animations : MonoBehaviour // TypeDefIndex: 2908
{
	// Fields
	private Animator MyAnimator; // 0x18

	// Constructors
	public Animations(); // 0x004071A0-0x004073A0

	// Methods
	private void Awake(); // 0x00406CE0-0x00406D20
	public void Walk(); // 0x00406D20-0x00406DB0
	public void WalkLeft(); // 0x00406DB0-0x00406E40
	public void WalkRight(); // 0x00406E40-0x00406ED0
	public void Idle(); // 0x00406ED0-0x00406F60
	public void Run(); // 0x00406F60-0x00406FF0
	public void RunLeft(); // 0x00406FF0-0x00407080
	public void RunRight(); // 0x00407080-0x00407110
	public void Jump(); // 0x00407110-0x004071A0
}

public class APITest : MonoBehaviour // TypeDefIndex: 2909
{
	// Fields
	public GameObject Follower1; // 0x18
	public GameObject Follower2; // 0x20
	private SPData SPData; // 0x28

	// Constructors
	public APITest(); // 0x00405CD0-0x00405D10

	// Methods
	public void Start(); // 0x00405A20-0x00405B90
	private void FollowerSettings(SPData SPData); // 0x00405B90-0x00405CD0
}

public class OvalShape : MonoBehaviour // TypeDefIndex: 2910
{
	// Fields
	public float Power; // 0x18
	private SPData SPData; // 0x20

	// Constructors
	public OvalShape(); // 0x003B0000-0x003B0050

	// Methods
	private void Start(); // 0x003AFD50-0x003B0000
}

[ExecuteInEditMode] // 0x00254C50-0x00254C60
public class RuntimeControl : MonoBehaviour // TypeDefIndex: 2911
{
	// Fields
	private SPData SPData; // 0x18
	private Transform SelectedPathPoint; // 0x20
	private action _transform; // 0x28
	private Vector3 screenPoint; // 0x2C
	private Vector3 offset; // 0x38
	private float rotSpeed; // 0x44

	// Nested types
	public enum action // TypeDefIndex: 2912
	{
		Translation = 0,
		Rotation = 1
	}

	// Constructors
	public RuntimeControl(); // 0x003C1EA0-0x003C1EF0

	// Methods
	private void Start(); // 0x003C0D70-0x003C0DC0
	private void Update(); // 0x003C0DC0-0x003C0DE0
	private void SelectPathPoint(); // 0x003C0DE0-0x003C1520
	private void ChangeTransform(); // 0x003C1520-0x003C1740
	private void OnMouseDown(); // 0x003C1740-0x003C1AB0
	private void OnMouseDrag(); // 0x003C1AB0-0x003C1EA0
}

public class SplinePlusWheel : MonoBehaviour // TypeDefIndex: 2913
{
	// Fields
	public SplinePlus SplinePlus; // 0x18
	public Transform wheel1; // 0x20
	public Transform wheel2; // 0x28

	// Constructors
	public SplinePlusWheel(); // 0x003D42C0-0x003D4300

	// Methods
	private void Update(); // 0x003D4020-0x003D42C0
}

public static class BranchesClass // TypeDefIndex: 2914
{
	// Nested types
	private sealed class <>c__DisplayClass2_0 // TypeDefIndex: 2915
	{
		// Fields
		public Node pathPoint1; // 0x10
		public SPData SPData; // 0x18
		public Node pathPoint2; // 0x20
		public Predicate<SharedNode> <>9__3; // 0x28

		// Constructors
		public <>c__DisplayClass2_0(); // 0x003D7FE0-0x003D7FF0

		// Methods
		internal bool <BranchWeldSt>b__0(SharedNode v); // 0x003D7FF0-0x003D80C0
		internal bool <BranchWeldSt>b__3(SharedNode x); // 0x003D80C0-0x003D80F0
		internal bool <BranchWeldSt>b__1(SharedNode x); // 0x003D80F0-0x003D8120
		internal bool <BranchWeldSt>b__2(SharedNode x); // 0x003D8120-0x003D8150
	}

	private sealed class <>c__DisplayClass5_0 // TypeDefIndex: 2916
	{
		// Fields
		public SPData SPData; // 0x10

		// Constructors
		public <>c__DisplayClass5_0(); // 0x003D8150-0x003D8160
	}

	private sealed class <>c__DisplayClass5_1 // TypeDefIndex: 2917
	{
		// Fields
		public int ii; // 0x10
		public <>c__DisplayClass5_0 CS$<>8__locals1; // 0x18
		public Predicate<Node> <>9__0; // 0x20

		// Constructors
		public <>c__DisplayClass5_1(); // 0x003D8160-0x003D8170

		// Methods
		internal bool <ConnectedBranches>b__0(Node x); // 0x003D8170-0x003D8200
	}

	private sealed class <>c__DisplayClass6_0 // TypeDefIndex: 2918
	{
		// Fields
		public Node node; // 0x10

		// Constructors
		public <>c__DisplayClass6_0(); // 0x003D8200-0x003D8210

		// Methods
		internal bool <AddRefreshSharedNode>b__0(SharedNode x); // 0x003D8210-0x003D8240
	}

	// Methods
	public static void BranchWeldSt(SPData SPData); // 0x00407A40-0x00407C90
	public static void ConnectedBranches(SPData SPData); // 0x00407C90-0x004080D0
	public static void AddRefreshSharedNode(SPData SPData, Node node); // 0x004080D0-0x00408230
	public static void ReverseBranch(SPData SPData, int branchKey); // 0x00408230-0x00408330
	public static void FlipHandles(SPData SPData, int branchKey, int nodeIndex); // 0x00408330-0x004084E0
}

public static class DistanceDataClass // TypeDefIndex: 2919
{
	// Methods
	public static DistanceData DataExtraction(SPData SPData, Follower follower, bool isForward, bool flipDirection); // 0x00359D40-0x0035AAA0
}

public class EventClass // TypeDefIndex: 2920
{
	// Methods
	public void EventsTriggering(Follower follower, int PreviousBranchKey, int CurrentBranchKey); // 0x0035F3B0-0x0035F540
	public void EventsTriggering(Train train, int PreviousBranchKey, int CurrentBranchKey); // 0x0035F540-0x0035F6D0
}

public class FollowerClass // TypeDefIndex: 2921
{
	// Nested types
	private sealed class <>c__DisplayClass14_0 // TypeDefIndex: 2922
	{
		// Fields
		public SharedNode sharedNode; // 0x10
		public SPData SPData; // 0x18
		public Follower follower; // 0x20

		// Constructors
		public <>c__DisplayClass14_0(); // 0x003DAD90-0x003DADA0

		// Methods
		internal int <DefinedSharedNodeType>b__0(); // 0x003DADA0-0x003DAF20
	}

	// Methods
	public void Follow(SPData SPData); // 0x0035FA20-0x0035FC70
	public void AnimationType(SPData SPData, Follower follower); // 0x0035FC70-0x00360270
	public void AutoAnimated(SPData SPData, Follower follower); // 0x00360270-0x003605C0
	public void IsAtBranchFork(SPData SPData, Follower follower); // 0x00360F70-0x003611D0
	public bool ProgressCheck(SPData SPData, Follower follower); // 0x00360EF0-0x00360F70
	public void KeyboardAnimationType(SPData SPData, Follower follower); // 0x003605C0-0x00360A40
	public void TransformFollower(SPData SPData, Follower follower); // 0x00360A40-0x00360EF0
	public void FollowerProjection(Follower follower); // 0x00361C50-0x00362800
	public float InputGravity(Follower follower, string state); // 0x00362800-0x00362F20
	public static bool IsBranchValid(SPData SPData, int previousBranchIndex, int newBranchKey, Node node); // 0x00361340-0x00361680
	private void BranchPicking(SPData SPData, SharedNode sharedNode, Follower follower); // 0x003611D0-0x00361340
	public void Branch_Picking_SharedNode(SPData SPData, SharedNode sharedNode, Follower follower, List<int> connectedBranches); // 0x00361680-0x00361780
	public void SetFollowerBranchKey(SPData SPData, SharedNode sharedNode, Follower follower, int branchKey); // 0x00361A80-0x00361C50
	public int DefinedSharedNodeType(SPData SPData, List<int> connectedBranches, SharedNode sharedNode, Follower follower); // 0x00361780-0x00361A80
}

public class GizmosClass // TypeDefIndex: 2923
{
	// Nested types
	private sealed class <>c__DisplayClass1_0 // TypeDefIndex: 2924
	{
		// Fields
		public int branchInd; // 0x10

		// Constructors
		public <>c__DisplayClass1_0(); // 0x003DAF20-0x003DAF30

		// Methods
		internal bool <DrawBranch>b__0(PathFindingPathPoint x); // 0x003DAF30-0x003DAF50
	}

	// Methods
	public void FollowerProjectionLines(Follower follower); // 0x00364A40-0x00365050
	public void DrawBranch(SPData SPData, Branch branch, int branchInd); // 0x00365050-0x00365AC0
	public void NodesGizmos(SPData SPData); // 0x00365AC0-0x00365FF0
}

public class Info : MonoBehaviour // TypeDefIndex: 2925
{
	// Fields
	public string Text; // 0x18

	// Constructors
	public Info(); // 0x00366D00-0x00366D40
}

public class PathGenerator : MonoBehaviour // TypeDefIndex: 2926
{
	// Fields
	public List<GameObject> Points; // 0x18
	public float Radius; // 0x20

	// Constructors
	public PathGenerator(); // 0x003B31D0-0x003B3260

	// Methods
	public void CreatePath(); // 0x003B2CB0-0x003B31D0
}

public class ProjectionClass // TypeDefIndex: 2927
{
	// Methods
	public void ProjectSpline(SPData SPData); // 0x003B71D0-0x003B7EA0
}

public enum FollowerAnimation // TypeDefIndex: 2928
{
	AutoAnimated = 0,
	KeyboardInput = 1,
	SceneClick = 2
}

public enum SharedNodeType // TypeDefIndex: 2929
{
	Random = 0,
	Defined = 1
}

public enum RefAxis // TypeDefIndex: 2930
{
	X = 0,
	Y = 1,
	Z = 2
}

public enum NodeType // TypeDefIndex: 2931
{
	Free = 0,
	Smooth = 1,
	Broken = 2
}

public enum BranchWeldState // TypeDefIndex: 2932
{
	none = 0,
	First = 1,
	Last = 2,
	Both = 3
}

public enum Modifiers // TypeDefIndex: 2933
{
	None = 0,
	MeshDeformer = 1,
	Extrude = 2,
	PlaneMesh = 3,
	TubeMesh = 4
}

public enum FollowerType // TypeDefIndex: 2934
{
	Simple = 0,
	Train = 1,
	PathFinding = 2
}

public enum UpdateType // TypeDefIndex: 2935
{
	None = 0,
	SharedNodes = 1
}

public enum PathFollowingType // TypeDefIndex: 2936
{
	Strict = 0,
	Projected = 1
}

[Serializable]
public class SPData : ISerializationCallbackReceiver // TypeDefIndex: 2937
{
	// Fields
	public RefAxis ReferenceAxis; // 0x10
	public Modifiers Modifiers; // 0x14
	public FollowerType FollowerType; // 0x18
	public List<Follower> Followers; // 0x20
	public List<Train> Trains; // 0x28
	public List<PathFindingGoal> PFFollowers; // 0x30
	public List<SharedNode> SharedNodes; // 0x38
	public SmoothData SmoothData; // 0x40
	public Selections Selections; // 0x48
	public static SharedSettings SharedSettings; // 0x00
	public int Smoothness; // 0x50
	public int PathPointCount; // 0x54
	public int BranchesCount; // 0x58
	public float Offset; // 0x5C
	public static float KeyboardInputValue; // 0x40
	public float RaycastLength; // 0x60
	public float SmoothRadius; // 0x64
	public bool InterpolateRotation; // 0x68
	public bool ShowProjectionRays; // 0x69
	public bool ContinuosProjectionUpdate; // 0x6A
	public bool HandlesProjection; // 0x6B
	public bool MeshOrientation; // 0x6C
	public bool ConstantSpeed; // 0x6D
	public bool EditSpline; // 0x6E
	public bool ShowNodeSettings; // 0x6F
	public bool ShowProjectionSettings; // 0x70
	public bool ShowSplineSettings; // 0x71
	public bool ShowSplineModifiers; // 0x72
	public bool ShowEvents; // 0x73
	public bool IsEditingPivot; // 0x74
	public bool IsLooped; // 0x75
	public Vector3 Pivot; // 0x78
	public SplinePlus AttachedSplinePlus; // 0x88
	public GameObject DataParent; // 0x90
	public SplinePlus SplinePlus; // 0x98
	public Dictionary<int, Branch> DictBranches; // 0xA0
	[SerializeField] // 0x00254ED0-0x00254EE0
	private List<int> Keys; // 0xA8
	[SerializeField] // 0x00254EE0-0x00254EF0
	private List<Branch> Values; // 0xB0

	// Constructors
	public SPData(); // 0x003C21D0-0x003C2340

	// Methods
	public void OnBeforeSerialize(); // 0x003C1EF0-0x003C2080
	public void OnAfterDeserialize(); // 0x003C2080-0x003C21D0
}

[Serializable]
public struct SharedSettings // TypeDefIndex: 2938
{
	// Fields
	public bool ShowHelper; // 0x00
	public bool ShowGizmos; // 0x01
	public bool ShowSecondaryHandles; // 0x02
	public float HelperSize; // 0x04
	public float GizmosSize; // 0x08
	public Color StandardPathPointColor; // 0x0C
	public Color RandomSharedNodeColor; // 0x1C
	public Color DefinedSharedNodeColor; // 0x2C
	public NodeType NodeType; // 0x3C
}

[Serializable]
public class Selections // TypeDefIndex: 2939
{
	// Fields
	public int _BranchKey; // 0x10
	public int _Follower; // 0x14
	public int _Agent; // 0x18
	public int _SharedPathPointIndex; // 0x1C
	public BranchWeldState _BranchWeldState; // 0x20
	public int _LocalNodeIndex; // 0x24

	// Constructors
	public Selections(); // 0x003C36A0-0x003C36B0
}

[Serializable]
public class Branch // TypeDefIndex: 2940
{
	// Fields
	public List<Vector3> Vertices; // 0x10
	public List<Vector3> Tangents; // 0x18
	public List<Vector3> Normals; // 0x20
	public List<Quaternion> VerticesRotation; // 0x28
	public List<Node> Nodes; // 0x30
	public List<float> SpeedFactor; // 0x38
	public List<float> VerticesDistance; // 0x40
	public float BranchDistance; // 0x48

	// Constructors
	public Branch(); // 0x00407920-0x00407A40
}

[Serializable]
public class SharedNode // TypeDefIndex: 2941
{
	// Fields
	public Node Node; // 0x10
	public List<int> ConnectedBranches; // 0x18
	public SharedNodeType _Type; // 0x20
	public int _Left; // 0x24
	public int _Right; // 0x28
	public int _Forward; // 0x2C
	public int _Backward; // 0x30

	// Constructors
	public SharedNode(); // 0x003CA790-0x003CA810
}

[Serializable]
public struct DistanceData // TypeDefIndex: 2942
{
	// Fields
	public int Index; // 0x00
	public Vector3 Position; // 0x04
	public Quaternion Rotation; // 0x10
}

[Serializable]
public class Follower // TypeDefIndex: 2943
{
	// Fields
	public int _BranchKey; // 0x10
	public GameObject FollowerGO; // 0x18
	public float Progress; // 0x20
	public float Acceleration; // 0x24
	public float BrakesForce; // 0x28
	public float UpdateTime; // 0x2C
	public FollowerAnimation _FollowerAnimation; // 0x30
	public UpdateType UpdateType; // 0x34
	public PathFollowingType PathFollowingType; // 0x38
	public Vector3 Position; // 0x3C
	public Vector3 Rotation; // 0x48
	public float Speed; // 0x54
	public float KeyGravity; // 0x58
	public float MinDistance; // 0x5C
	public float OnAwakeDelayTime; // 0x60
	public float Delta; // 0x64
	public bool IsForward; // 0x68
	public bool Reverse; // 0x69
	public bool Rot; // 0x6A
	public bool LocalTranslation; // 0x6B
	public bool FlipDirection; // 0x6C
	public bool IsActive; // 0x6D
	public bool AnimationEvents; // 0x6E
	public bool Show; // 0x6F
	public bool GoalReached; // 0x70
	public bool GoalFound; // 0x71
	public bool IsMinDist; // 0x72
	public bool ConsiderTangents; // 0x73
	public DistanceData DistanceData; // 0x74
	public UnityEvent OnMoveEvent; // 0x98
	public UnityEvent IDLEEvent; // 0xA0
	public UnityEvent SpaceEvent; // 0xA8
	public UnityEvent OnAwakeEvent; // 0xB0
	public FollowerProjection FollowerProjection; // 0xB8
	public List<SplinePlusEvent> Events; // 0xC0
	public List<PathFindingPathPoint> PathFindingPath; // 0xC8

	// Constructors
	public Follower(); // 0x0035F8D0-0x0035FA10
}

[Serializable]
public class PathFindingGoal // TypeDefIndex: 2944
{
	// Fields
	public Follower Goal; // 0x10
	public List<Follower> Agents; // 0x18
	public bool Show; // 0x20

	// Constructors
	public PathFindingGoal(); // 0x003B2C50-0x003B2CA0
}

[Serializable]
public class Train // TypeDefIndex: 2945
{
	// Fields
	public string Name; // 0x10
	public List<Follower> Wagons; // 0x18
	public float Step; // 0x20
	public bool Show; // 0x24
	public bool IsForward; // 0x25
	public bool IsActive; // 0x26
	public bool IsEndRoad; // 0x27
	public bool AnimationEvents; // 0x28
	public int _BranchKey; // 0x2C
	public float Progress; // 0x30
	public float Speed; // 0x34
	public float KeyGravity; // 0x38
	public float OnAwakeDelayTime; // 0x3C
	public float Acceleration; // 0x40
	public float BrakesForce; // 0x44
	public FollowerAnimation _FollowerAnimation; // 0x48
	public Vector3 Position; // 0x4C
	public Vector3 Rotation; // 0x58
	public UnityEvent OnMoveEvent; // 0x68
	public UnityEvent IDLEEvent; // 0x70
	public UnityEvent SpaceEvent; // 0x78
	public UnityEvent OnAwakeEvent; // 0x80
	public List<SplinePlusEvent> Events; // 0x88

	// Constructors
	public Train(); // 0x003D49B0-0x003D4AB0
}

[Serializable]
public class Node // TypeDefIndex: 2946
{
	// Fields
	public Transform Point; // 0x10
	public Transform Point1; // 0x18
	public Transform Point2; // 0x20
	public NodeType _Type; // 0x28
	public int SpeedFactor; // 0x2C
	public int NormalFactor; // 0x30
	public float Distance; // 0x34
	public Vector3 Normal; // 0x38
	public Vector3 Tangent; // 0x44

	// Constructors
	public Node(); // 0x003A9240-0x003A9250

	// Methods
	public int LocalIndex(SPData SPData, int branchKey); // 0x003A8F20-0x003A9020
	public override bool Equals(object obj); // 0x003A9020-0x003A9210
	public override int GetHashCode(); // 0x003A9210-0x003A9240
}

[Serializable]
public class SplinePlusEvent // TypeDefIndex: 2947
{
	// Fields
	public string EventName; // 0x10
	public UnityEvent MyEvents; // 0x18
	public string BranchIndexEndStr; // 0x20
	public string BranchIndexStartStr; // 0x28
	public int _Condition; // 0x30
	public List<string> Conditions; // 0x38
	public bool AnimationEvents; // 0x40

	// Constructors
	public SplinePlusEvent(); // 0x003D3FA0-0x003D4020
}

[Serializable]
public class SmoothData // TypeDefIndex: 2948
{
	// Fields
	public bool IsShared; // 0x10
	public bool SmoothNode; // 0x11
	public Vector3 InitNodePos; // 0x14
	public Vector3 InitNodePoint1Pos; // 0x20
	public Node[] Nodes; // 0x30
	public int[] BranchesIndices; // 0x38
	public List<int> newBranchesIndices; // 0x40
	public bool[] FlippedPathPoint; // 0x48
	public int InitBranchesCount; // 0x50

	// Constructors
	public SmoothData(); // 0x003CA960-0x003CA9F0
}

[Serializable]
public class PathFindingPathPoint // TypeDefIndex: 2949
{
	// Fields
	public Node Curr; // 0x10
	public int BranchIndex; // 0x18

	// Constructors
	public PathFindingPathPoint(); // 0x003B2CA0-0x003B2CB0
}

[Serializable]
public class FollowerProjection // TypeDefIndex: 2950
{
	// Fields
	public float GroundRayLength; // 0x10
	public float ObstacleRayLength; // 0x14
	public Transform RayTransform; // 0x18
	public bool GroundColDetect; // 0x20
	public bool ObstacleColDetect; // 0x21
	public bool FollowGroundNormal; // 0x22

	// Constructors
	public FollowerProjection(); // 0x0035FA10-0x0035FA20
}

public class SplineCreationClass // TypeDefIndex: 2951
{
	// Methods
	public void UpdateAllBranches(SPData SPData); // 0x003CC1A0-0x003CC350
	public void UpdateBranch(SPData SPData, Branch branch); // 0x003CC350-0x003CC560
	public void CubicBezier(SPData SPData, Branch branch, Node pointA, Node pointB); // 0x003CEF80-0x003D0740
	public void UpdateComponents(SPData SPData); // 0x003CCC20-0x003CCC90
	private void FindSubPackages(SPData SPData, string type); // 0x003CCC90-0x003CCF50
	private Vector3 CalculateCubicBezier(float t, Vector3 p0, Vector3 p1, Vector3 p2, Vector3 p3); // 0x003D0740-0x003D0930
	private Vector3 CalculateTangent(float t, Vector3 p0, Vector3 p1, Vector3 p2, Vector3 p3); // 0x003D0930-0x003D0B60
}

public class SplinePlus : MonoBehaviour // TypeDefIndex: 2952
{
	// Fields
	public SPData SPData; // 0x18
	public FollowerClass FollowerClass; // 0x20
	public TrainClass TrainClass; // 0x28
	public SplineCreationClass SplineCreationClass; // 0x30
	public EventClass EventClass; // 0x38
	public ProjectionClass ProjectionClass; // 0x40
	public GizmosClass GizmosClass; // 0x48

	// Nested types
	private sealed class <OnAwakeFollowerEvent>d__9 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2953
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public Follower follower; // 0x20
		public SplinePlus <>4__this; // 0x28

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255D90-0x00255DA0 */ get; } // 0x003E7500-0x003E7510
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255DA0-0x00255DB0 */ get; } // 0x003E7510-0x003E7520

		// Constructors
		[DebuggerHidden] // 0x00255D70-0x00255D80
		public <OnAwakeFollowerEvent>d__9(int <>1__state); // 0x003D0FD0-0x003D0FE0

		// Methods
		[DebuggerHidden] // 0x00255D80-0x00255D90
		void IDisposable.Dispose(); // 0x003E7420-0x003E7430
		private bool MoveNext(); // 0x003E7430-0x003E7500
	}

	// Constructors
	public SplinePlus(); // 0x003D0B70-0x003D0D20

	// Methods
	private void Start(); // 0x003D0D20-0x003D0F70
	private IEnumerator OnAwakeFollowerEvent(Follower follower); // 0x003D0F70-0x003D0FD0
	private void Update(); // 0x003D0FE0-0x003D1020
	public void PFFollow(); // 0x003CC950-0x003CCC20
	public void PFFindPath(Follower agent, PathFindingGoal pFGoal); // 0x003D1020-0x003D1480
	public void PFFindAllShortestPaths(); // 0x003D1480-0x003D17B0
	public void SelectFollower(int followerIndex); // 0x003D17B0-0x003D17D0
	public void SetSpeed(float Speed); // 0x003D17D0-0x003D1850
	public void SetProgress(float Progress); // 0x003D1850-0x003D18D0
	public void GoToNewBranch(int Index); // 0x003D18D0-0x003D1940
	public static T CreateInstance<T>(T type);
	private void OnDrawGizmosSelected(); // 0x003D1940-0x003D1AE0
}

public static class SplinePlusAPI // TypeDefIndex: 2954
{
	// Nested types
	private sealed class <>c__DisplayClass6_0 // TypeDefIndex: 2955
	{
		// Fields
		public Node node; // 0x10
		public Predicate<Node> <>9__0; // 0x18

		// Constructors
		public <>c__DisplayClass6_0(); // 0x003D3310-0x003D3320

		// Methods
		internal bool <IsSharedPathPoint>b__0(Node x); // 0x003E7520-0x003E7550
	}

	// Methods
	public static SPData CreateSplinePlus(Vector3 pos); // 0x003D1AE0-0x003D1C00
	public static void SmoothAllSharedNodes(SPData SPData, float radius); // 0x003D1C00-0x003D1CC0
	public static void SmoothSharedNode(SPData SPData, SharedNode sharedNode, float radius); // 0x003D1CC0-0x003D26F0
	public static int ConnectTwoNodes(SPData SPData, Node pathPoint1, Node pathPoint2); // 0x003D2D80-0x003D3150
	public static void IsSharedPathPoint(SPData SPData, Node node, int currentBranchIndex); // 0x003D3150-0x003D3310
	public static Node CreateNode(SPData SPData, Vector3 position, bool weld = true /* Metadata: 0x0015AD53 */); // 0x003D3320-0x003D3C70
	public static Node DuplicatePathPoint(SPData SPData, Node originPathPoint); // 0x003D26F0-0x003D2D80
}

public class SplinePlusAnimation : MonoBehaviour // TypeDefIndex: 2956
{
	// Fields
	private Animator Animator; // 0x18
	private SplinePlus SplinePlus; // 0x20

	// Constructors
	public SplinePlusAnimation(); // 0x003D3F60-0x003D3FA0

	// Methods
	private void Start(); // 0x003D3C70-0x003D3CC0
	private void Update(); // 0x003D3CC0-0x003D3F60
}

public class TrainClass // TypeDefIndex: 2957
{
	// Nested types
	public struct data // TypeDefIndex: 2958
	{
		// Fields
		public Follower wagon; // 0x00
		public Train train; // 0x08
		public int i; // 0x10
	}

	// Methods
	public void Follow(SPData SPData); // 0x003CC560-0x003CC950
	public void AnimationType(SPData SPData, data data); // 0x003CCF50-0x003CD0A0
	public bool ProgressCheck(SPData SPData, data data); // 0x003D4AB0-0x003D4B30
	public void AutoAnimated(SPData SPData, data data); // 0x003CD0A0-0x003CD490
	public void KeyboardAnimationType(SPData SPData, data data); // 0x003CD490-0x003CD990
	public static void TransformFollower(SPData SPData, data data); // 0x003CE300-0x003CE810
	public void InputGravity(data data, string state, int trainHeadIndex); // 0x003CE810-0x003CEF80
	public void AtBranchFork(SPData SPData, data data); // 0x003CD990-0x003CDDC0
	private void BranchPicking(SPData SPData, SharedNode sharedNode, data data); // 0x003CDDC0-0x003CDFC0
	public static void SetTrainBranchKey(SPData SPData, SharedNode sharedNode, data data, int branchKey); // 0x003CE110-0x003CE300
	public int Branch_Picking_SharedNode(SPData SPData, SharedNode sharedNode, data data, List<int> connectedBranches); // 0x003CDFC0-0x003CE110
}

public class ETFXProjectileScript : MonoBehaviour // TypeDefIndex: 2959
{
	// Fields
	public GameObject impactParticle; // 0x18
	public GameObject projectileParticle; // 0x20
	public GameObject muzzleParticle; // 0x28
	public float colliderRadius; // 0x30
	public float collideOffset; // 0x34

	// Constructors
	public ETFXProjectileScript(); // 0x0035DEB0-0x0035DF00

	// Methods
	private void Start(); // 0x0035CC60-0x0035D070
	private void FixedUpdate(); // 0x0035D070-0x0035DEB0
}

public class ETFXSceneManager : MonoBehaviour // TypeDefIndex: 2960
{
	// Fields
	public bool GUIHide; // 0x18
	public bool GUIHide2; // 0x19
	public bool GUIHide3; // 0x1A
	public bool GUIHide4; // 0x1B

	// Constructors
	public ETFXSceneManager(); // 0x0035EB90-0x0035EBD0

	// Methods
	public void LoadScene2DDemo(); // 0x0035E1E0-0x0035E210
	public void LoadSceneCards(); // 0x0035E210-0x0035E240
	public void LoadSceneCombat(); // 0x0035E240-0x0035E270
	public void LoadSceneDecals(); // 0x0035E270-0x0035E2A0
	public void LoadSceneDecals2(); // 0x0035E2A0-0x0035E2D0
	public void LoadSceneEmojis(); // 0x0035E2D0-0x0035E300
	public void LoadSceneEmojis2(); // 0x0035E300-0x0035E330
	public void LoadSceneExplosions(); // 0x0035E330-0x0035E360
	public void LoadSceneExplosions2(); // 0x0035E360-0x0035E390
	public void LoadSceneFire(); // 0x0035E390-0x0035E3C0
	public void LoadSceneFire2(); // 0x0035E3C0-0x0035E3F0
	public void LoadSceneFire3(); // 0x0035E3F0-0x0035E420
	public void LoadSceneFireworks(); // 0x0035E420-0x0035E450
	public void LoadSceneFlares(); // 0x0035E450-0x0035E480
	public void LoadSceneMagic(); // 0x0035E480-0x0035E4B0
	public void LoadSceneMagic2(); // 0x0035E4B0-0x0035E4E0
	public void LoadSceneMagic3(); // 0x0035E4E0-0x0035E510
	public void LoadSceneMainDemo(); // 0x0035E510-0x0035E540
	public void LoadSceneMissiles(); // 0x0035E540-0x0035E570
	public void LoadScenePortals(); // 0x0035E570-0x0035E5A0
	public void LoadScenePortals2(); // 0x0035E5A0-0x0035E5D0
	public void LoadScenePowerups(); // 0x0035E5D0-0x0035E600
	public void LoadScenePowerups2(); // 0x0035E600-0x0035E630
	public void LoadSceneSparkles(); // 0x0035E630-0x0035E660
	public void LoadSceneSwordCombat(); // 0x0035E660-0x0035E690
	public void LoadSceneSwordCombat2(); // 0x0035E690-0x0035E6C0
	public void LoadSceneMoney(); // 0x0035E6C0-0x0035E6F0
	public void LoadSceneHealing(); // 0x0035E6F0-0x0035E720
	public void LoadSceneWind(); // 0x0035E720-0x0035E750
	private void Update(); // 0x0035E750-0x0035EB90
}

public enum ButtonTypes // TypeDefIndex: 2961
{
	NotDefined = 0,
	Previous = 1,
	Next = 2
}

public class PEButtonScript : MonoBehaviour, IEventSystemHandler, IPointerEnterHandler, IPointerExitHandler // TypeDefIndex: 2962
{
	// Fields
	private Button myButton; // 0x18
	public ButtonTypes ButtonType; // 0x20

	// Constructors
	public PEButtonScript(); // 0x003B01D0-0x003B0210

	// Methods
	private void Start(); // 0x003B0050-0x003B00D0
	public void OnPointerEnter(PointerEventData eventData); // 0x003B00D0-0x003B0120
	public void OnPointerExit(PointerEventData eventData); // 0x003B0120-0x003B0170
	public void OnButtonClicked(); // 0x003B0170-0x003B01D0
}

public class ParticleEffectsLibrary : MonoBehaviour // TypeDefIndex: 2963
{
	// Fields
	public static ParticleEffectsLibrary GlobalAccess; // 0x00
	public int TotalEffects; // 0x18
	public int CurrentParticleEffectIndex; // 0x1C
	public int CurrentParticleEffectNum; // 0x20
	public Vector3[] ParticleEffectSpawnOffsets; // 0x28
	public float[] ParticleEffectLifetimes; // 0x30
	public GameObject[] ParticleEffectPrefabs; // 0x38
	private string effectNameString; // 0x40
	private List<Transform> currentActivePEList; // 0x48
	private Vector3 spawnPosition; // 0x50

	// Constructors
	public ParticleEffectsLibrary(); // 0x003B2080-0x003B2160

	// Methods
	private void Awake(); // 0x003B0580-0x003B0AC0
	public string GetCurrentPENameString(); // 0x003B0AC0-0x003B0F30
	public void PreviousParticleEffect(); // 0x003B0F30-0x003B15E0
	public void NextParticleEffect(); // 0x003B15E0-0x003B1CA0
	public void SpawnParticleEffect(Vector3 positionInWorldToSpawn); // 0x003B1CA0-0x003B2080
}

public class UICanvasManager : MonoBehaviour // TypeDefIndex: 2964
{
	// Fields
	public static UICanvasManager GlobalAccess; // 0x00
	public bool MouseOverButton; // 0x18
	public Text PENameText; // 0x20
	public Text ToolTipText; // 0x28
	private RaycastHit rayHit; // 0x30

	// Constructors
	public UICanvasManager(); // 0x003D53E0-0x003D5420

	// Methods
	private void Awake(); // 0x003D4B30-0x003D4B70
	private void Start(); // 0x003D4B70-0x003D4CB0
	private void Update(); // 0x003D4CB0-0x003D4D90
	public void UpdateToolTip(ButtonTypes toolTipType); // 0x003D5170-0x003D52A0
	public void ClearToolTip(); // 0x003D52A0-0x003D53C0
	private void SelectPreviousPE(); // 0x003D4EB0-0x003D5010
	private void SelectNextPE(); // 0x003D5010-0x003D5170
	private void SpawnCurrentParticleEffect(); // 0x003D4D90-0x003D4EB0
	public void UIButtonClick(ButtonTypes buttonTypeClicked); // 0x003D53C0-0x003D53E0
}

public class GameSettings : MonoBehaviour // TypeDefIndex: 2965
{
	// Fields
	public static GameSettings instance; // 0x00
	public static GameObject Ocean; // 0x08
	public static GameObject OceanLevel; // 0x10
	public static GameObject PostProcessing; // 0x18
	public static GameObject Camera; // 0x20
	public static bool renderOcean; // 0x28
	public static bool renderTrees; // 0x29
	public static bool otherPlayers; // 0x2A
	public static bool postProcessing; // 0x2B
	public static bool renderFancyLights; // 0x2C
	public static float detailDensity; // 0x30
	public static int screenwidth; // 0x34
	public static int screenheight; // 0x38
	public static bool fullscreen; // 0x3C
	public static float audioVolume; // 0x40
	public static float mouseSensitivity; // 0x44
	public static bool cursorVisible; // 0x48

	// Constructors
	public GameSettings(); // 0x00364770-0x003647B0
	static GameSettings(); // 0x003647B0-0x003648A0

	// Methods
	private void Awake(); // 0x00363320-0x00363370
	private void Start(); // 0x00363370-0x00363C20
	public static void SetPostProcessing(bool state); // 0x00363C20-0x00363D70
	public static void SetOtherPlayers(bool state); // 0x00364710-0x00364770
	public static void RenderTrees(bool state); // 0x00363D70-0x00364040
	public static void DetailDensity(float density); // 0x00364040-0x00364230
	public static void AudioVolume(float volume); // 0x00364430-0x00364620
	public static void MouseSensitivity(float sensitivity); // 0x00364230-0x00364430
	public static void UpdateScreen(int width, int height, bool _fullscreen); // 0x00364620-0x00364710
}

public class GenerateMaze : MonoBehaviour // TypeDefIndex: 2966
{
	// Constructors
	public GenerateMaze(); // 0x00364A00-0x00364A40
}

public class Highscore : MonoBehaviour // TypeDefIndex: 2967
{
	// Fields
	public TMP_Text[] t_highscores; // 0x18
	public TMP_Text[] t_personal_highscores; // 0x20
	public ServerManager serverManager; // 0x28

	// Nested types
	private sealed class <updateHighscoreLoop>d__4 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2968
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public Highscore <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255DD0-0x00255DE0 */ get; } // 0x003DB710-0x003DB720
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255DE0-0x00255DF0 */ get; } // 0x003DB720-0x003DB730

		// Constructors
		[DebuggerHidden] // 0x00255DB0-0x00255DC0
		public <updateHighscoreLoop>d__4(int <>1__state); // 0x003DB630-0x003DB640

		// Methods
		[DebuggerHidden] // 0x00255DC0-0x00255DD0
		void IDisposable.Dispose(); // 0x003DB640-0x003DB650
		private bool MoveNext(); // 0x003DB650-0x003DB710
	}

	private sealed class <updateHighscore>d__5 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2969
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public Highscore <>4__this; // 0x20
		private UnityWebRequest <www>5__2; // 0x28
		private string <apihost>5__3; // 0x30

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255E10-0x00255E20 */ get; } // 0x003DB610-0x003DB620
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255E20-0x00255E30 */ get; } // 0x003DB620-0x003DB630

		// Constructors
		[DebuggerHidden] // 0x00255DF0-0x00255E00
		public <updateHighscore>d__5(int <>1__state); // 0x003DAF50-0x003DAF60

		// Methods
		[DebuggerHidden] // 0x00255E00-0x00255E10
		void IDisposable.Dispose(); // 0x003DAF60-0x003DAF70
		private bool MoveNext(); // 0x003DAF70-0x003DB610
	}

	// Constructors
	public Highscore(); // 0x003669C0-0x00366A00

	// Methods
	private void Start(); // 0x00366850-0x00366920
	private IEnumerator updateHighscoreLoop(); // 0x00366920-0x00366970
	public IEnumerator updateHighscore(); // 0x00366970-0x003669C0
}

public class HoverEffect : MonoBehaviour // TypeDefIndex: 2970
{
	// Fields
	[SerializeField] // 0x00254EF0-0x00254F00
	private float rangeFactor; // 0x18
	private Vector3 initialPosition; // 0x1C
	[SerializeField] // 0x00254F00-0x00254F10
	private float speed; // 0x28
	[SerializeField] // 0x00254F10-0x00254F20
	private ServerManager server; // 0x30

	// Constructors
	public HoverEffect(); // 0x00366CB0-0x00366D00

	// Methods
	private void Start(); // 0x00366A00-0x00366AC0
	private void FixedUpdate(); // 0x00366AC0-0x00366CB0
}

public class InformTrigger : MonoBehaviour // TypeDefIndex: 2971
{
	// Fields
	[SerializeField] // 0x00254F20-0x00254F30
	private UnityEvent triggerEvent; // 0x18
	[SerializeField] // 0x00254F30-0x00254F40
	private bool triggerOnce; // 0x20
	[SerializeField] // 0x00254F40-0x00254F50
	private InformTrigger dependsOn; // 0x28
	public bool triggered; // 0x30
	public bool ready_to_fire; // 0x31

	// Constructors
	public InformTrigger(); // 0x00366F50-0x00366FA0

	// Methods
	private void emitEvent(); // 0x00366D40-0x00366F30
	private void OnTriggerStay(Collider other); // 0x00366F30-0x00366F40
	private void OnTriggerEnter(Collider other); // 0x00366F40-0x00366F50
}

public class ScrollingUVs_Layers : MonoBehaviour // TypeDefIndex: 2972
{
	// Fields
	public Vector2 uvAnimationRate; // 0x18
	public string textureName; // 0x20
	private Vector2 uvOffset; // 0x28

	// Constructors
	public ScrollingUVs_Layers(); // 0x003C35C0-0x003C36A0

	// Methods
	private void LateUpdate(); // 0x003C3430-0x003C35C0
}

public class MainMenu : MonoBehaviour // TypeDefIndex: 2973
{
	// Fields
	private int port_min; // 0x18
	private int port_max; // 0x1C
	private string hostname; // 0x20
	private string username; // 0x28
	private string userpassword; // 0x30
	private int controlledby; // 0x38
	private string[] name; // 0x40
	public TMP_InputField i_hostname; // 0x48
	public TMP_InputField i_userpassword; // 0x50
	public TMP_InputField i_username; // 0x58
	public TMP_InputField i_port_min; // 0x60
	public TMP_InputField i_port_max; // 0x68
	public TMP_Text t_status; // 0x70
	public TMP_Text t_welcome; // 0x78
	public GameObject loginButton; // 0x80
	public GameObject retryButton; // 0x88
	public TMP_Dropdown i_controlledby; // 0x90
	private System.Random random; // 0x98

	// Nested types
	private sealed class <getConfig>d__19 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2974
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public MainMenu <>4__this; // 0x20
		private bool <server_healthy>5__2; // 0x28
		private UnityWebRequest <www>5__3; // 0x30
		private string[] <>7__wrap3; // 0x38
		private int <>7__wrap4; // 0x40
		private string <apihost>5__6; // 0x48

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255E50-0x00255E60 */ get; } // 0x003DD120-0x003DD130
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255E60-0x00255E70 */ get; } // 0x003DD130-0x003DD140

		// Constructors
		[DebuggerHidden] // 0x00255E30-0x00255E40
		public <getConfig>d__19(int <>1__state); // 0x003DB730-0x003DB740

		// Methods
		[DebuggerHidden] // 0x00255E40-0x00255E50
		void IDisposable.Dispose(); // 0x003DB740-0x003DB750
		private bool MoveNext(); // 0x003DB750-0x003DD120
	}

	// Constructors
	public MainMenu(); // 0x00370790-0x003723F0

	// Methods
	public string RandomString(int length); // 0x0036F8E0-0x0036FA20
	private IEnumerator getConfig(); // 0x0036FA20-0x0036FA70
	private void Start(); // 0x0036FA70-0x0036FDA0
	public void retryServer(); // 0x0036FDA0-0x0036FE90
	private void initUI(); // 0x0036FE90-0x00370120
	private void startGame(); // 0x00370120-0x00370260
	public void setMazeHostname(); // 0x00370260-0x00370740
	public void setInputHostname(); // 0x00370740-0x00370790
	private char <RandomString>b__18_0(string s); // 0x003723F0-0x00372480
}

[ExecuteInEditMode] // 0x00254C60-0x00254C70
public class ListMeshVertCount : MonoBehaviour // TypeDefIndex: 2975
{
	// Fields
	public bool includeInActive; // 0x18
	public bool listVertCount; // 0x19

	// Constructors
	public ListMeshVertCount(); // 0x0036BC90-0x0036BCD0

	// Methods
	private void Update(); // 0x0036B6A0-0x0036B6B0
	private void ListVertCount(); // 0x0036B6B0-0x0036BC90
}

[ExecuteInEditMode] // 0x00254C70-0x00254C80
public class EnableChildrenMeshRenderers : MonoBehaviour // TypeDefIndex: 2976
{
	// Fields
	public bool execute; // 0x18

	// Constructors
	public EnableChildrenMeshRenderers(); // 0x0035F360-0x0035F3A0

	// Methods
	private void Update(); // 0x0035F270-0x0035F280
	private void Execute(); // 0x0035F280-0x0035F360
}

public class NPCController : MonoBehaviour // TypeDefIndex: 2977
{
	// Fields
	[SerializeField] // 0x00254F50-0x00254F60
	private Vector3 current_position; // 0x18
	[SerializeField] // 0x00254F60-0x00254F70
	private Vector3 next_position; // 0x24
	[SerializeField] // 0x00254F70-0x00254F80
	private SkinnedMeshRenderer rabbitRenderer; // 0x30
	[SerializeField] // 0x00254F80-0x00254F90
	private TMP_Text hoverName; // 0x38
	[SerializeField] // 0x00254F90-0x00254FA0
	private Canvas hoverCanvas; // 0x40
	[SerializeField] // 0x00254FA0-0x00254FB0
	private ServerManager serverManager; // 0x48
	[SerializeField] // 0x00254FB0-0x00254FC0
	private string npc_name; // 0x50
	[SerializeField] // 0x00254FC0-0x00254FD0
	private ushort unlocks; // 0x58
	private bool new_info; // 0x5A
	public uint uid; // 0x5C
	[SerializeField] // 0x00254FD0-0x00254FE0
	private Material[] materials; // 0x60
	private float current_groundblend; // 0x68
	private float next_groundblend; // 0x6C
	public float lastUpdatedTime; // 0x70
	private float current_notgroundblend; // 0x74
	private float next_notgroundblend; // 0x78
	private bool disable_position_updates; // 0x7C
	[SerializeField] // 0x00254FE0-0x00254FF0
	private Vector3 current_rotation; // 0x80
	[SerializeField] // 0x00254FF0-0x00255000
	private Vector3 next_rotation; // 0x8C
	[SerializeField] // 0x00255000-0x00255010
	private Quaternion current_quaternion; // 0x98
	[SerializeField] // 0x00255010-0x00255020
	private Quaternion next_quaternion; // 0xA8
	[SerializeField] // 0x00255020-0x00255030
	private GameObject animation; // 0xB8
	[SerializeField] // 0x00255030-0x00255040
	private TrailRenderer trail; // 0xC0
	[SerializeField] // 0x00255040-0x00255050
	private GameObject[] emojiAnimation; // 0xC8
	public uint last_emoji; // 0xD0
	[SerializeField] // 0x00255050-0x00255060
	private float transitionSpeed; // 0xD4
	[SerializeField] // 0x00255060-0x00255070
	private float animationSpeed; // 0xD8
	private float transition; // 0xDC
	private float animationTransition; // 0xE0
	private bool candestroy; // 0xE4
	private Animator animator; // 0xE8
	private bool destroyStarted; // 0xF0

	// Nested types
	private sealed class <requestInfo>d__32 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2978
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public NPCController <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255E90-0x00255EA0 */ get; } // 0x003E3060-0x003E3070
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255EA0-0x00255EB0 */ get; } // 0x003E3070-0x003E3080

		// Constructors
		[DebuggerHidden] // 0x00255E70-0x00255E80
		public <requestInfo>d__32(int <>1__state); // 0x003E2FC0-0x003E2FD0

		// Methods
		[DebuggerHidden] // 0x00255E80-0x00255E90
		void IDisposable.Dispose(); // 0x003E2FD0-0x003E2FE0
		private bool MoveNext(); // 0x003E2FE0-0x003E3060
	}

	private sealed class <disablePositionUpdatesFor4s>d__40 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2979
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public NPCController <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255ED0-0x00255EE0 */ get; } // 0x003E2FA0-0x003E2FB0
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255EE0-0x00255EF0 */ get; } // 0x003E2FB0-0x003E2FC0

		// Constructors
		[DebuggerHidden] // 0x00255EB0-0x00255EC0
		public <disablePositionUpdatesFor4s>d__40(int <>1__state); // 0x003E2E60-0x003E2E70

		// Methods
		[DebuggerHidden] // 0x00255EC0-0x00255ED0
		void IDisposable.Dispose(); // 0x003E2E70-0x003E2E80
		private bool MoveNext(); // 0x003E2E80-0x003E2FA0
	}

	private sealed class <showAnimation>d__45 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2980
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public NPCController <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255F10-0x00255F20 */ get; } // 0x003E31C0-0x003E31D0
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255F20-0x00255F30 */ get; } // 0x003E31D0-0x003E31E0

		// Constructors
		[DebuggerHidden] // 0x00255EF0-0x00255F00
		public <showAnimation>d__45(int <>1__state); // 0x003E3080-0x003E3090

		// Methods
		[DebuggerHidden] // 0x00255F00-0x00255F10
		void IDisposable.Dispose(); // 0x003E3090-0x003E30A0
		private bool MoveNext(); // 0x003E30A0-0x003E31C0
	}

	private sealed class <showEmoji>d__46 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2981
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ushort _emoji; // 0x20
		public NPCController <>4__this; // 0x28

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255F50-0x00255F60 */ get; } // 0x003E33C0-0x003E33D0
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255F60-0x00255F70 */ get; } // 0x003E33D0-0x003E33E0

		// Constructors
		[DebuggerHidden] // 0x00255F30-0x00255F40
		public <showEmoji>d__46(int <>1__state); // 0x003E31E0-0x003E31F0

		// Methods
		[DebuggerHidden] // 0x00255F40-0x00255F50
		void IDisposable.Dispose(); // 0x003E31F0-0x003E3200
		private bool MoveNext(); // 0x003E3200-0x003E33C0
	}

	// Constructors
	public NPCController(); // 0x003A8EC0-0x003A8F20

	// Methods
	private void Start(); // 0x003A7510-0x003A7920
	private IEnumerator requestInfo(); // 0x003A7CB0-0x003A7D00
	public void setNewInfo(string _name, ushort _unlocks); // 0x003A7D00-0x003A7D20
	public void triggerGrounded(); // 0x003A7D20-0x003A7DB0
	public void triggerAttack1(); // 0x003A7DB0-0x003A7E40
	public void triggerAttack2(); // 0x003A7E40-0x003A7ED0
	public void triggerGroundedWall(); // 0x003A7ED0-0x003A7F60
	public void triggerNotGrounded(); // 0x003A7F60-0x003A7FF0
	public void triggerDeath(); // 0x003A7FF0-0x003A80E0
	private IEnumerator disablePositionUpdatesFor4s(); // 0x003A80E0-0x003A8130
	public void setGroundedBlend(float blend); // 0x003A8130-0x003A8150
	public void setNotGroundedBlend(float blend); // 0x003A8150-0x003A8170
	private void setPosition(Vector3 new_position); // 0x003A7BD0-0x003A7CB0
	public void newPosition(Vector3 new_position, Vector3 new_rotation); // 0x003A7920-0x003A7BD0
	private IEnumerator showAnimation(); // 0x003A8170-0x003A81C0
	public IEnumerator showEmoji(ushort _emoji); // 0x003A81C0-0x003A8210
	private void FixedUpdate(); // 0x003A8210-0x003A8E40
}

public class RaceManager : MonoBehaviour // TypeDefIndex: 2982
{
	// Fields
	[SerializeField] // 0x00255070-0x00255080
	private GameObject[] checkpoints; // 0x18
	[SerializeField] // 0x00255080-0x00255090
	private ServerManager serverManager; // 0x20
	[SerializeField] // 0x00255090-0x002550A0
	private Highscore highscore; // 0x28
	private float last_checkpoint; // 0x30
	private int last_checkpoint_id; // 0x34
	private bool raceRunning; // 0x38
	private bool reachedFinishline; // 0x39

	// Constructors
	public RaceManager(); // 0x003B84B0-0x003B84F0

	// Methods
	private void Start(); // 0x003B7EA0-0x003B7FC0
	public void gotCheckpoint(int checkpoint_id, float time); // 0x003B7FC0-0x003B8060
	private void Update(); // 0x003B8060-0x003B8430
}

public class SceneLoader : MonoBehaviour // TypeDefIndex: 2983
{
	// Fields
	public TMP_Text t_progress; // 0x18

	// Nested types
	private sealed class <LoadYourAsyncScene>d__3 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2984
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public SceneLoader <>4__this; // 0x20
		private AsyncOperation <asyncLoad>5__2; // 0x28

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255F90-0x00255FA0 */ get; } // 0x003E5FD0-0x003E5FE0
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255FA0-0x00255FB0 */ get; } // 0x003E5FE0-0x003E5FF0

		// Constructors
		[DebuggerHidden] // 0x00255F70-0x00255F80
		public <LoadYourAsyncScene>d__3(int <>1__state); // 0x003E5BB0-0x003E5BC0

		// Methods
		[DebuggerHidden] // 0x00255F80-0x00255F90
		void IDisposable.Dispose(); // 0x003E5BC0-0x003E5BD0
		private bool MoveNext(); // 0x003E5BD0-0x003E5FD0
	}

	// Constructors
	public SceneLoader(); // 0x003C33F0-0x003C3430

	// Methods
	private void Start(); // 0x003C3350-0x003C33A0
	private IEnumerator LoadYourAsyncScene(); // 0x003C33A0-0x003C33F0
}

public class UILoader : MonoBehaviour // TypeDefIndex: 2985
{
	// Fields
	public GameObject toggle1; // 0x18
	public GameObject toggle2; // 0x20
	public ServerManager serverManager; // 0x28

	// Constructors
	public UILoader(); // 0x003D5FA0-0x003D5FE0

	// Methods
	private void Start(); // 0x003D5810-0x003D5850
	private void Update(); // 0x003D5850-0x003D5FA0
}

public class ServerManager : MonoBehaviour // TypeDefIndex: 2986
{
	// Fields
	[SerializeField] // 0x002550A0-0x002550B0
	private GameSettings gameSettings; // 0x18
	[SerializeField] // 0x002550B0-0x002550C0
	private CharacterBrain brain; // 0x20
	[SerializeField] // 0x002550C0-0x002550D0
	private GameObject playerCharacter; // 0x28
	[SerializeField] // 0x002550D0-0x002550E0
	private GameObject playerCharacterGraphics; // 0x30
	[SerializeField] // 0x002550E0-0x002550F0
	private Animator playerAnimator; // 0x38
	[SerializeField] // 0x002550F0-0x00255100
	private SkinnedMeshRenderer rabbitRenderer; // 0x40
	[SerializeField] // 0x00255100-0x00255110
	private Material[] materials; // 0x48
	[SerializeField] // 0x00255110-0x00255120
	private TrailRenderer trail; // 0x50
	[SerializeField] // 0x00255120-0x00255130
	private GameObject[] teleporters; // 0x58
	[SerializeField] // 0x00255130-0x00255140
	private GameObject[] locked_teleporters; // 0x60
	[SerializeField] // 0x00255140-0x00255150
	private GameObject npcPrefab; // 0x68
	[SerializeField] // 0x00255150-0x00255160
	private RaceManager racemanager; // 0x70
	[SerializeField] // 0x00255160-0x00255170
	private TextMeshProUGUI t_server; // 0x78
	private string t_server_text; // 0x80
	[SerializeField] // 0x00255170-0x00255180
	private TextMeshProUGUI t_fps; // 0x88
	private string t_fps_text; // 0x90
	[SerializeField] // 0x00255180-0x00255190
	private GameObject gameOver; // 0x98
	[SerializeField] // 0x00255190-0x002551A0
	private GameObject emojibar; // 0xA0
	private bool emojibar_active; // 0xA8
	[SerializeField] // 0x002551A0-0x002551B0
	private GameObject flagScreen; // 0xB0
	private string flag_text; // 0xB8
	private float flag_duration; // 0xC0
	[SerializeField] // 0x002551B0-0x002551C0
	private GameObject discoverScreen; // 0xC8
	private string discover_text; // 0xD0
	private bool uglyCode; // 0xD8
	[SerializeField] // 0x002551C0-0x002551D0
	private GameObject black_screen; // 0xE0
	private bool black_screen_active; // 0xE8
	[SerializeField] // 0x002551D0-0x002551E0
	private byte version; // 0xE9
	[SerializeField] // 0x002551E0-0x002551F0
	private TextMeshProUGUI t_error; // 0xF0
	private string t_error_text; // 0xF8
	public bool loggedIn; // 0x100
	private bool play_death_animation; // 0x101
	private bool disable_gameover; // 0x102
	[SerializeField] // 0x002551F0-0x00255200
	private Dictionary<uint, NPCController> players; // 0x108
	private float heartbeat_roundtrip; // 0x110
	[SerializeField] // 0x00255200-0x00255210
	private bool onlinePlay; // 0x114
	public float rate_limit; // 0x118
	private ConcurrentQueue<NPCInit> instantiateQueue; // 0x120
	private ConcurrentQueue<NPCInit> eventQueue; // 0x128
	private UdpClient client; // 0x130
	private IPEndPoint anyIP; // 0x138
	private string host; // 0x140
	private int port; // 0x148
	private Thread threadRecv; // 0x150
	private bool recvLoop; // 0x158
	private string username; // 0x160
	private uint uid; // 0x168
	public ushort unlocks; // 0x16C
	private bool got_new_unlock; // 0x16E
	public byte[] usersecret; // 0x170
	public float time; // 0x178
	public float server_time; // 0x17C
	private long start_server_time; // 0x180
	private float lastUpdate; // 0x188
	public float lastServerPacket; // 0x18C
	public float loginAttempt; // 0x190
	public float lastHeartbeat; // 0x194
	private byte trigger; // 0x198
	private short groundedblend; // 0x19A
	private short notgroundedblend; // 0x19C
	private float teleport_player_x; // 0x1A0
	private float teleport_player_y; // 0x1A4
	private float teleport_player_z; // 0x1A8
	private byte teleport_instant; // 0x1AC
	private bool teleport_ready; // 0x1AD
	private bool blocking_position_updates; // 0x1AE
	public bool enable_movement; // 0x1AF
	public bool disable_movement; // 0x1B0
	private System.Random rand; // 0x1B8
	private bool otherPlayers; // 0x1C0
	private Vector3 position; // 0x1C4
	private Vector3 eulerAngles; // 0x1D0
	private Vector3 current_position; // 0x1DC
	private Vector3 current_eulerAngles; // 0x1E8
	[SerializeField] // 0x00255210-0x00255220
	private GameObject unlockAnimation; // 0x1F8
	[SerializeField] // 0x00255220-0x00255230
	private GameObject[] emojiAnimation; // 0x200
	[SerializeField] // 0x00255230-0x00255240
	private GameObject[] emojiUI; // 0x208
	private ushort emoji; // 0x210
	private uint new_emoji; // 0x214
	private uint last_emoji; // 0x218
	public float teleport_x; // 0x21C
	public float teleport_y; // 0x220
	public float teleport_z; // 0x224
	private Color fps_color; // 0x228
	private float noPlayerMultiplier; // 0x238
	private bool movementEnabled; // 0x23C

	// Nested types
	private class NPCInit // TypeDefIndex: 2987
	{
		// Fields
		public uint uid; // 0x10
		public ulong time; // 0x18
		public Vector3 position; // 0x20
		public Vector3 eulerAngle; // 0x2C
		public GameObject obj; // 0x38
		public byte player_trigger; // 0x40
		public float player_grounded; // 0x44
		public float player_notgrounded; // 0x48
		public ushort emoji; // 0x4C
		public uint emoji_time; // 0x50

		// Constructors
		public NPCInit(); // 0x003E6D20-0x003E6D30
	}

	private sealed class <showAnimation>d__82 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2988
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ServerManager <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00255FD0-0x00255FE0 */ get; } // 0x003E6B00-0x003E6B10
		object IEnumerator.Current { [DebuggerHidden] /* 0x00255FE0-0x00255FF0 */ get; } // 0x003E6B10-0x003E6B20

		// Constructors
		[DebuggerHidden] // 0x00255FB0-0x00255FC0
		public <showAnimation>d__82(int <>1__state); // 0x003E69C0-0x003E69D0

		// Methods
		[DebuggerHidden] // 0x00255FC0-0x00255FD0
		void IDisposable.Dispose(); // 0x003E69D0-0x003E69E0
		private bool MoveNext(); // 0x003E69E0-0x003E6B00
	}

	private sealed class <delayedStart>d__83 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2989
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ServerManager <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256010-0x00256020 */ get; } // 0x003E69A0-0x003E69B0
		object IEnumerator.Current { [DebuggerHidden] /* 0x00256020-0x00256030 */ get; } // 0x003E69B0-0x003E69C0

		// Constructors
		[DebuggerHidden] // 0x00255FF0-0x00256000
		public <delayedStart>d__83(int <>1__state); // 0x003E6900-0x003E6910

		// Methods
		[DebuggerHidden] // 0x00256000-0x00256010
		void IDisposable.Dispose(); // 0x003E6910-0x003E6920
		private bool MoveNext(); // 0x003E6920-0x003E69A0
	}

	private sealed class <LoginLoop>d__91 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2990
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ServerManager <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256050-0x00256060 */ get; } // 0x003E6530-0x003E6540
		object IEnumerator.Current { [DebuggerHidden] /* 0x00256060-0x00256070 */ get; } // 0x003E6540-0x003E6550

		// Constructors
		[DebuggerHidden] // 0x00256030-0x00256040
		public <LoginLoop>d__91(int <>1__state); // 0x003E6190-0x003E61A0

		// Methods
		[DebuggerHidden] // 0x00256040-0x00256050
		void IDisposable.Dispose(); // 0x003E61A0-0x003E61B0
		private bool MoveNext(); // 0x003E61B0-0x003E6530
	}

	private sealed class <ShowFlag>d__111 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2991
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ServerManager <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256090-0x002560A0 */ get; } // 0x003E68E0-0x003E68F0
		object IEnumerator.Current { [DebuggerHidden] /* 0x002560A0-0x002560B0 */ get; } // 0x003E68F0-0x003E6900

		// Constructors
		[DebuggerHidden] // 0x00256070-0x00256080
		public <ShowFlag>d__111(int <>1__state); // 0x003E6700-0x003E6710

		// Methods
		[DebuggerHidden] // 0x00256080-0x00256090
		void IDisposable.Dispose(); // 0x003E6710-0x003E6720
		private bool MoveNext(); // 0x003E6720-0x003E68E0
	}

	private sealed class <ShowDiscover>d__112 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2992
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ServerManager <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x002560D0-0x002560E0 */ get; } // 0x003E66E0-0x003E66F0
		object IEnumerator.Current { [DebuggerHidden] /* 0x002560E0-0x002560F0 */ get; } // 0x003E66F0-0x003E6700

		// Constructors
		[DebuggerHidden] // 0x002560B0-0x002560C0
		public <ShowDiscover>d__112(int <>1__state); // 0x003E6550-0x003E6560

		// Methods
		[DebuggerHidden] // 0x002560C0-0x002560D0
		void IDisposable.Dispose(); // 0x003E6560-0x003E6570
		private bool MoveNext(); // 0x003E6570-0x003E66E0
	}

	private sealed class <DeathAnimation>d__113 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2993
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ServerManager <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256110-0x00256120 */ get; } // 0x003E6170-0x003E6180
		object IEnumerator.Current { [DebuggerHidden] /* 0x00256120-0x00256130 */ get; } // 0x003E6180-0x003E6190

		// Constructors
		[DebuggerHidden] // 0x002560F0-0x00256100
		public <DeathAnimation>d__113(int <>1__state); // 0x003E5FF0-0x003E6000

		// Methods
		[DebuggerHidden] // 0x00256100-0x00256110
		void IDisposable.Dispose(); // 0x003E6000-0x003E6010
		private bool MoveNext(); // 0x003E6010-0x003E6170
	}

	private sealed class <showEmoji>d__114 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2994
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ushort _emoji; // 0x20
		public ServerManager <>4__this; // 0x28

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256150-0x00256160 */ get; } // 0x003E6D00-0x003E6D10
		object IEnumerator.Current { [DebuggerHidden] /* 0x00256160-0x00256170 */ get; } // 0x003E6D10-0x003E6D20

		// Constructors
		[DebuggerHidden] // 0x00256130-0x00256140
		public <showEmoji>d__114(int <>1__state); // 0x003E6B20-0x003E6B30

		// Methods
		[DebuggerHidden] // 0x00256140-0x00256150
		void IDisposable.Dispose(); // 0x003E6B30-0x003E6B40
		private bool MoveNext(); // 0x003E6B40-0x003E6D00
	}

	// Constructors
	public ServerManager(); // 0x003CA5D0-0x003CA790

	// Methods
	private void Start(); // 0x003C36B0-0x003C3820
	private IEnumerator showAnimation(); // 0x003C3870-0x003C38C0
	private IEnumerator delayedStart(); // 0x003C3820-0x003C3870
	private void OnDestroy(); // 0x003C38C0-0x003C3900
	public void teleportForward(); // 0x003C3900-0x003C3B30
	public void toggleAIHuman(); // 0x003C3B30-0x003C3B90
	private void Login(); // 0x003C3B90-0x003C41A0
	private IEnumerator LoginLoop(); // 0x003C41A0-0x003C41F0
	private string ByteToHex(byte[] ba); // 0x003C41F0-0x003C42C0
	public string getSecret(); // 0x003C42C0-0x003C4390
	private void UpdateServerPosition(bool force); // 0x003C4390-0x003C4CB0
	public void sendEmoji(ushort _emoji); // 0x003C5020-0x003C5110
	private bool sendData(byte[] pkt); // 0x003C4CB0-0x003C5020
	public void SendInfoRequest(uint uid); // 0x003C5110-0x003C51F0
	private void sendHeartbeat(); // 0x003C51F0-0x003C5330
	public void setGroundedBlend(float blend); // 0x003C5330-0x003C5350
	public void setNotGroundedBlend(float blend); // 0x003C5350-0x003C5370
	public void setAnimatorBlend(float blendgrounded, float blendnotgrounded); // 0x003C5370-0x003C53A0
	private bool compareBytes(byte[] b1, byte[] b2); // 0x003C53A0-0x003C53F0
	private void RecieveDataThread(); // 0x003C53F0-0x003C7EB0
	public void showText(string msg); // 0x003B8430-0x003B84B0
	public void setTriggerGrounded(); // 0x003C7EB0-0x003C7ED0
	public void setTriggerNotGrounded(); // 0x003C7ED0-0x003C7EF0
	public void setTriggerAttack1(); // 0x003C7EF0-0x003C7F10
	public void setTriggerAttack2(); // 0x003C7F10-0x003C7F30
	public void setTriggerGroundedWall(); // 0x003C7F30-0x003C7F50
	public void setTriggerDeath(); // 0x003C7F50-0x003C7F70
	private IEnumerator ShowFlag(); // 0x003C7F70-0x003C7FC0
	private IEnumerator ShowDiscover(); // 0x003C7FC0-0x003C8010
	private IEnumerator DeathAnimation(); // 0x003C8010-0x003C8060
	private IEnumerator showEmoji(ushort _emoji); // 0x003C8060-0x003C80B0
	public void removePlayer(uint uid); // 0x003A8E40-0x003A8EC0
	private void Update(); // 0x003C80B0-0x003CA5D0
}

public class ShowText : MonoBehaviour // TypeDefIndex: 2995
{
	// Fields
	private TMP_Text text; // 0x18
	public string showText; // 0x20

	// Nested types
	private sealed class <AnimateText>d__5 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2996
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public ShowText <>4__this; // 0x20
		private int <i>5__2; // 0x28

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256190-0x002561A0 */ get; } // 0x003E6F30-0x003E6F40
		object IEnumerator.Current { [DebuggerHidden] /* 0x002561A0-0x002561B0 */ get; } // 0x003E6F40-0x003E6F50

		// Constructors
		[DebuggerHidden] // 0x00256170-0x00256180
		public <AnimateText>d__5(int <>1__state); // 0x003E6D30-0x003E6D40

		// Methods
		[DebuggerHidden] // 0x00256180-0x00256190
		void IDisposable.Dispose(); // 0x003E6D40-0x003E6D50
		private bool MoveNext(); // 0x003E6D50-0x003E6F30
	}

	// Constructors
	public ShowText(); // 0x003CA8F0-0x003CA960

	// Methods
	private void Start(); // 0x003CA810-0x003CA850
	public void startAnimatingText(); // 0x003CA850-0x003CA8A0
	private IEnumerator AnimateText(); // 0x003CA8A0-0x003CA8F0
}

[Serializable]
public class SplineEvent // TypeDefIndex: 2997
{
	// Fields
	public float progress; // 0x10
	public UnityEvent triggerEvent; // 0x18
	public bool triggered; // 0x20

	// Constructors
	public SplineEvent(); // 0x003D0B60-0x003D0B70
}

public class SplineController : MonoBehaviour // TypeDefIndex: 2998
{
	// Fields
	private SplinePlus sp; // 0x18
	[SerializeField] // 0x00255240-0x00255250
	private Animator animator; // 0x20
	public string initTrigger; // 0x28
	[SerializeField] // 0x00255250-0x00255260
	private List<SplineEvent> EventList; // 0x30
	public InformTrigger state2_to_3_trigger; // 0x38
	public InformTrigger state3_to_4_trigger; // 0x40

	// Nested types
	private sealed class <state5_delay3s_walk>d__11 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 2999
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public SplineController <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x002561D0-0x002561E0 */ get; } // 0x003E7400-0x003E7410
		object IEnumerator.Current { [DebuggerHidden] /* 0x002561E0-0x002561F0 */ get; } // 0x003E7410-0x003E7420

		// Constructors
		[DebuggerHidden] // 0x002561B0-0x002561C0
		public <state5_delay3s_walk>d__11(int <>1__state); // 0x003E7330-0x003E7340

		// Methods
		[DebuggerHidden] // 0x002561C0-0x002561D0
		void IDisposable.Dispose(); // 0x003E7340-0x003E7350
		private bool MoveNext(); // 0x003E7350-0x003E7400
	}

	private sealed class <state5_continue_walk>d__13 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 3000
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public SplineController <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256210-0x00256220 */ get; } // 0x003E7310-0x003E7320
		object IEnumerator.Current { [DebuggerHidden] /* 0x00256220-0x00256230 */ get; } // 0x003E7320-0x003E7330

		// Constructors
		[DebuggerHidden] // 0x002561F0-0x00256200
		public <state5_continue_walk>d__13(int <>1__state); // 0x003E71E0-0x003E71F0

		// Methods
		[DebuggerHidden] // 0x00256200-0x00256210
		void IDisposable.Dispose(); // 0x003E71F0-0x003E7200
		private bool MoveNext(); // 0x003E7200-0x003E7310
	}

	private sealed class <state3_to_4_delayed>d__17 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 3001
	{
		// Fields
		private int <>1__state; // 0x10
		private object <>2__current; // 0x18
		public SplineController <>4__this; // 0x20

		// Properties
		object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256250-0x00256260 */ get; } // 0x003E71C0-0x003E71D0
		object IEnumerator.Current { [DebuggerHidden] /* 0x00256260-0x00256270 */ get; } // 0x003E71D0-0x003E71E0

		// Constructors
		[DebuggerHidden] // 0x00256230-0x00256240
		public <state3_to_4_delayed>d__17(int <>1__state); // 0x003E6F50-0x003E6F60

		// Methods
		[DebuggerHidden] // 0x00256240-0x00256250
		void IDisposable.Dispose(); // 0x003E6F60-0x003E6F70
		private bool MoveNext(); // 0x003E6F70-0x003E71C0
	}

	// Constructors
	public SplineController(); // 0x003CC100-0x003CC1A0

	// Methods
	public void EnableTrigger(InformTrigger trigger); // 0x003CB0F0-0x003CB110
	private void Start(); // 0x003CB110-0x003CB220
	private void Update(); // 0x003CB220-0x003CB980
	public void state1_start_walking(); // 0x003CB980-0x003CBA70
	public void state5_dig_down(); // 0x003CBA70-0x003CBBA0
	private IEnumerator state5_delay3s_walk(); // 0x003CBBA0-0x003CBBF0
	public void state5_dig_up(); // 0x003CBBF0-0x003CBD00
	private IEnumerator state5_continue_walk(); // 0x003CBD00-0x003CBD50
	public void state2_first_pause(); // 0x003CBD50-0x003CBE40
	public void state3_before_jump(); // 0x003CBE40-0x003CBF70
	public void state7_disappear(); // 0x003CBFC0-0x003CC100
	private IEnumerator state3_to_4_delayed(); // 0x003CBF70-0x003CBFC0
}

public class UIMenu : MonoBehaviour // TypeDefIndex: 3002
{
	// Fields
	public GameObject SubMenuSettings; // 0x18
	public GameObject MainMenu; // 0x20
	public Slider DensitySlider; // 0x28
	public Slider VolumeSlider; // 0x30
	public Slider SensitivitySlider; // 0x38
	public Toggle FullscreenToggle; // 0x40
	public Toggle ToggleOceanRender; // 0x48
	public Toggle ToggleTreeGrass; // 0x50
	public Toggle ToggleFancyLight; // 0x58
	public Toggle TogglePostProcessing; // 0x60
	public Toggle ToggleOtherPlayers; // 0x68
	public TMP_Dropdown ResolutionDropdown; // 0x70
	public GameObject Ocean; // 0x78
	public GameObject OceanLevel; // 0x80
	public GameObject PostProcessing; // 0x88
	public GameObject Camera; // 0x90
	private List<Resolution> resolutions; // 0x98
	public bool renderOcean; // 0xA0
	public bool renderTrees; // 0xA1
	public bool postProcessing; // 0xA2
	public bool renderFancyLights; // 0xA3
	public bool otherPlayers; // 0xA4
	public float detailDensity; // 0xA8
	public int screenwidth; // 0xAC
	public int screenheight; // 0xB0
	public bool fullscreen; // 0xB4
	private string XaxisName; // 0xB8
	private string YaxisName; // 0xC0
	private bool ignoreEvents; // 0xC8
	private int lastScreenWidth; // 0xCC
	private int lastScreenHeight; // 0xD0

	// Constructors
	public UIMenu(); // 0x003D7000-0x003D7120

	// Methods
	private void EnableInputs(bool state); // 0x003D5FE0-0x003D6430
	private void OnDestroy(); // 0x003D6430-0x003D64C0
	private void Start(); // 0x003D64C0-0x003D6AB0
	public void NewGame(); // 0x003D6AB0-0x003D6AE0
	public void SettingsClicked(); // 0x003D6AE0-0x003D6BB0
	public void PostProcessingEvent(); // 0x003D6BB0-0x003D6C20
	public void OtherPlayersEvent(); // 0x003D6C20-0x003D6CF0
	public void RenderTreesEvent(); // 0x003D6CF0-0x003D6D60
	public void DetailDensityEvent(); // 0x003D6D60-0x003D6DF0
	public void VolumeEvent(); // 0x003D6DF0-0x003D6E80
	public void MouseSensitivityEvent(); // 0x003D6E80-0x003D6F10
	public void UpdateScreenEvent(); // 0x003D6F10-0x003D6FC0
	public void Exit(); // 0x003D6FC0-0x003D7000
}

public class Windmill : MonoBehaviour // TypeDefIndex: 3003
{
	// Fields
	[SerializeField] // 0x00255260-0x00255270
	private float speed; // 0x18
	private Vector3 initialPosition; // 0x1C
	[SerializeField] // 0x00255270-0x00255280
	private ServerManager server; // 0x28
	[SerializeField] // 0x00255280-0x00255290
	private Vector3 rotationDirection; // 0x30
	[SerializeField] // 0x00255290-0x002552A0
	private Vector3 current; // 0x3C

	// Constructors
	public Windmill(); // 0x003D7B90-0x003D7BE0

	// Methods
	private void Start(); // 0x003D78A0-0x003D7960
	private void FixedUpdate(); // 0x003D7960-0x003D7B90
}

namespace Nicrom.PM
{
	public enum HandlesPos // TypeDefIndex: 3004
	{
		OnGridMainRect = 0,
		OnHorizontalLines = 1,
		OnVerticalLines = 2
	}

	[Serializable]
	public class CustomGrid // TypeDefIndex: 3005
	{
		// Fields
		[SerializeField] // 0x002552A0-0x002552B0
		private HandlesPos handlesPos; // 0x10
		[SerializeField] // 0x002552B0-0x002552C0
		private List<float> vLinesOnCanvasGrid; // 0x18
		[SerializeField] // 0x002552C0-0x002552D0
		private List<float> hLinesOnCanvasGrid; // 0x20
		[SerializeField] // 0x002552D0-0x002552E0
		private TextureGrid tg; // 0x28
		[SerializeField] // 0x002552E0-0x002552F0
		private Rect gridOnCanvas; // 0x30
		public Vector2Int mouseInsideRectPos; // 0x40
		public Color32 gridColor; // 0x48
		public string gridLabel; // 0x50
		public bool editGridName; // 0x58
		public bool isSelected; // 0x59
		public bool showGridOptions; // 0x5A
		public bool isSelectionLocked; // 0x5B
		public bool isHandleSelected; // 0x5C
		private bool isDragged; // 0x5D
		public bool isGridPosLocked; // 0x5E
		public bool isOverlapping; // 0x5F
		public int handleID; // 0x60
		public List<int> vLinesOnTexGrid; // 0x68
		public List<int> hLinesOnTexGrid; // 0x70
		public Color32 tintColor; // 0x78
		public Color32 emptySpaceColor; // 0x7C
		public Vector2Int gridPos; // 0x80
		public int gridWidth; // 0x88
		public int gridHeight; // 0x8C
		public int gridColumns; // 0x90
		public int gridRows; // 0x94
		public bool hasEmptySpace; // 0x98
		public bool isTexPattern; // 0x99

		// Constructors
		public CustomGrid(); // 0x00357110-0x00357230
	}

	public enum ColorNumbering // TypeDefIndex: 3006
	{
		Continuous = 0,
		PerPalette = 1
	}

	public enum TextureUpdate // TypeDefIndex: 3007
	{
		Auto = 0,
		Manual = 1
	}

	public class PaletteModifier : MonoBehaviour // TypeDefIndex: 3008
	{
		// Fields
		public ColorNumbering colorNumbering; // 0x18
		public TextureUpdate textureUpdate; // 0x1C
		public List<Palette> palettesList; // 0x20
		public List<CellData> cellStorage; // 0x28
		public TextureGrid texGrid; // 0x30
		public Color32 gradStartColor; // 0x38
		public Color32 gradEndColor; // 0x3C
		public Color32 highlightColor; // 0x40
		public bool highlightSelectedColor; // 0x44
		public bool debug; // 0x45
		public bool generatePaletteModifierData; // 0x46
		public float colorBlend; // 0x48
		public int gradientStart; // 0x4C
		public int gradientEnd; // 0x50
		public int flatColorsOnObject; // 0x54
		public int texPatternsOnObject; // 0x58
		public int colorFieldsInInspector; // 0x5C
		public int flatColorsInInspector; // 0x60
		public string[] toolBarTitles; // 0x68
		public int selectedToolBar; // 0x70

		// Constructors
		public PaletteModifier(); // 0x003B0280-0x003B0580
	}

	[Serializable]
	public class Palette // TypeDefIndex: 3009
	{
		// Fields
		public List<CellData> cellsList; // 0x10
		public string paletteName; // 0x18
		public bool editPaletteName; // 0x20
		public bool isColorListExpanded; // 0x21
		public int elementHeight; // 0x24
		public int propFieldHeight; // 0x28

		// Constructors
		public Palette(); // 0x003B0210-0x003B0280
	}

	[Serializable]
	public class CellData // TypeDefIndex: 3010
	{
		// Fields
		public List<int> uvIndex; // 0x10
		public Color32 currentCellColor; // 0x18
		public Color32 previousCellColor; // 0x1C
		public Rect gridCell; // 0x20
		public bool isSelected; // 0x30
		public bool highlightColorApplied; // 0x31
		public bool isTexture; // 0x32
	}

	public enum GridColorMode // TypeDefIndex: 3011
	{
		RandomColor = 0,
		SingleColor = 1
	}

	public class TextureGrid : ScriptableObject // TypeDefIndex: 3012
	{
		// Fields
		public GridColorMode gridColorMode; // 0x18
		public Color gridColor; // 0x1C
		public List<CustomGrid> gridsList; // 0x30
		public List<CustomGrid> copyList; // 0x38
		public Texture2D texAtlas; // 0x40
		public Texture2D originTexAtlas; // 0x48
		public Vector2 originOffset; // 0x50
		public Vector2Int sizeOffset; // 0x58
		public bool showShortcuts; // 0x60
		public int zoomSpeed; // 0x64
		public int handleSize; // 0x68
		public int canvasBorder; // 0x6C
		public int panelDefaultWidth; // 0x70
		public int sidePanelWidth; // 0x74
		public bool showPanel; // 0x78
		public bool drawAxes; // 0x79
		public bool drawGrid; // 0x7A
		public Vector2Int texAtlasSize; // 0x7C

		// Constructors
		public TextureGrid(); // 0x003D4900-0x003D49B0
	}
}

namespace MeshCombineStudio
{
	public class DisabledLODGroup : MonoBehaviour // TypeDefIndex: 3013
	{
		// Fields
		public MeshCombiner meshCombiner; // 0x18
		public LODGroup lodGroup; // 0x20

		// Constructors
		public DisabledLODGroup(); // 0x00359C80-0x00359CC0
	}

	[ExecuteInEditMode] // 0x00254C80-0x00254C90
	public class FindLodGroups : MonoBehaviour // TypeDefIndex: 3014
	{
		// Fields
		public bool find; // 0x18

		// Constructors
		public FindLodGroups(); // 0x0035F890-0x0035F8D0

		// Methods
		private void Start(); // 0x0035F6E0-0x0035F6F0
		private void Update(); // 0x0035F880-0x0035F890
		private void FindLods(); // 0x0035F6F0-0x0035F880
	}

	public class LODGroupSetup : MonoBehaviour // TypeDefIndex: 3015
	{
		// Fields
		public MeshCombiner meshCombiner; // 0x18
		public LODGroup lodGroup; // 0x20
		public int lodGroupParentIndex; // 0x28
		public int lodCount; // 0x2C
		private LODGroup[] lodGroups; // 0x30

		// Constructors
		public LODGroupSetup(); // 0x00369CF0-0x00369D30

		// Methods
		public void Init(MeshCombiner meshCombiner, int lodGroupParentIndex); // 0x00368C20-0x00368D80
		private void GetSetup(); // 0x00368D80-0x00368EB0
		public void ApplySetup(); // 0x00368EB0-0x00369450
		public void AddLODGroupsToChildren(); // 0x00369450-0x00369A80
		public void RemoveLODGroupFromChildren(); // 0x00369A80-0x00369CF0
	}

	public class CamGeometryCapture : MonoBehaviour // TypeDefIndex: 3016
	{
		// Fields
		public ComputeShader computeDepthToArray; // 0x18
		public Int2 resolution; // 0x20
		public Camera cam; // 0x28
		public Transform t; // 0x30
		public RenderTexture rtCapture; // 0x38
		private float[] heights; // 0x40
		private Bounds bounds; // 0x48
		private float maxSize; // 0x60

		// Constructors
		public CamGeometryCapture(); // 0x0040A780-0x0040A7D0

		// Methods
		public void Init(); // 0x004085F0-0x004087C0
		private void OnDestroy(); // 0x004087C0-0x00408830
		private void DisposeRenderTexture(ref RenderTexture rt); // 0x00408830-0x004089A0
		public void DisposeRTCapture(); // 0x004089A0-0x00408A10
		public void RemoveTrianglesBelowSurface(Transform t, MeshCombineJobManager.MeshCombineJob meshCombineJob, MeshCache.SubMeshCache newMeshCache, ref byte[] vertexIsBelow); // 0x00408A10-0x00409170
		public void Capture(Bounds bounds, int collisionMask, Vector3 direction, Int2 resolution); // 0x00409170-0x004099D0
		public void SetCamera(Vector3 direction); // 0x0040A290-0x0040A780
		public float GetHeight(Vector3 pos); // 0x004099D0-0x0040A290
	}

	public class CombinedLODManager : MonoBehaviour // TypeDefIndex: 3017
	{
		// Fields
		public bool drawGizmos; // 0x18
		public LOD[] lods; // 0x20
		public float[] distances; // 0x28
		public LodDistanceMode lodDistanceMode; // 0x30
		public LodMode lodMode; // 0x34
		public int showLod; // 0x38
		public bool lodCulled; // 0x3C
		public float lodCullDistance; // 0x40
		public Vector3 octreeCenter; // 0x44
		public Vector3 octreeSize; // 0x50
		public int maxLevels; // 0x5C
		public bool search; // 0x60
		private Cell octree; // 0x68
		private Transform cameraMainT; // 0x70

		// Nested types
		public enum LodMode // TypeDefIndex: 3018
		{
			Automatic = 0,
			DebugLod = 1
		}

		public enum LodDistanceMode // TypeDefIndex: 3019
		{
			Automatic = 0,
			Manual = 1
		}

		[Serializable]
		public class LOD // TypeDefIndex: 3020
		{
			// Fields
			public Transform searchParent; // 0x10
			public Sphere3 sphere; // 0x18

			// Constructors
			public LOD(); // 0x003D9C60-0x003D9C70
		}

		public class Cell : BaseOctree.Cell // TypeDefIndex: 3021
		{
			// Fields
			public Cell[] cells; // 0x50
			private AABB3 box; // 0x58

			// Constructors
			public Cell(); // 0x003D8240-0x003D8250
			public Cell(Vector3 position, Vector3 size, int maxLevels); // 0x003D8250-0x003D8320

			// Methods
			public void AddMeshRenderer(MeshRenderer mr, Vector3 position, int lodLevel, int lodLevels); // 0x003D8320-0x003D8630
			private void AddMeshRendererInternal(MeshRenderer mr, Vector3 position, int lodLevel, int lodLevels); // 0x003D8630-0x003D8A40
			public void AutoLodInternal(LOD[] lods, float lodCulledDistance); // 0x003D8A40-0x003D91C0
			public void LodInternal(LOD[] lods, int lodLevel); // 0x003D91C0-0x003D9600
			public void DrawGizmos(LOD[] lods); // 0x003D9600-0x003D9780
			public void DrawGizmosInternal(); // 0x003D9780-0x003D9C60
		}

		public class MaxCell : Cell // TypeDefIndex: 3022
		{
			// Fields
			public List<MeshRenderer>[] mrList; // 0x70
			public int currentLod; // 0x78

			// Constructors
			public MaxCell(); // 0x003D9C70-0x003D9C80
		}

		// Constructors
		public CombinedLODManager(); // 0x004298F0-0x004299F0

		// Methods
		private void Awake(); // 0x00428CD0-0x00428D70
		private void InitOctree(); // 0x00428D70-0x00428E50
		private void Start(); // 0x00428E50-0x00428F50
		private void Update(); // 0x004291D0-0x004291F0
		public void UpdateLods(MeshCombiner meshCombiner, int lodAmount); // 0x00429340-0x00429620
		public void UpdateDistances(MeshCombiner meshCombiner); // 0x00429620-0x00429690
		public void Search(); // 0x00428F50-0x004291D0
		public void ResetOctree(); // 0x00429690-0x004298C0
		public void Lod(LodMode lodMode); // 0x004291F0-0x00429340
		private void OnDrawGizmosSelected(); // 0x004298C0-0x004298F0
	}

	[ExecuteInEditMode] // 0x00254C90-0x00254CA0
	public class MeshCombineJobManager : MonoBehaviour // TypeDefIndex: 3023
	{
		// Fields
		public static MeshCombineJobManager instance; // 0x00
		public JobSettings jobSettings; // 0x18
		[NonSerialized]
		public FastList<NewMeshObject> newMeshObjectsPool; // 0x20
		public Dictionary<Mesh, MeshCache> meshCacheDictionary; // 0x28
		[NonSerialized]
		public int totalNewMeshObjects; // 0x30
		public Queue<MeshCombineJob> meshCombineJobs; // 0x38
		public MeshCombineJobsThread[] meshCombineJobsThreads; // 0x40
		public CamGeometryCapture camGeometryCapture; // 0x48
		public int cores; // 0x50
		public int threadAmount; // 0x54
		public int startThreadId; // 0x58
		public int endThreadId; // 0x5C
		public bool abort; // 0x60
		private MeshCache.SubMeshCache tempMeshCache; // 0x68
		private Ray ray; // 0x70
		private RaycastHit hitInfo; // 0x88

		// Nested types
		[Serializable]
		public class JobSettings // TypeDefIndex: 3024
		{
			// Fields
			public CombineJobMode combineJobMode; // 0x10
			public ThreadAmountMode threadAmountMode; // 0x14
			public int combineMeshesPerFrame; // 0x18
			public bool useMultiThreading; // 0x1C
			public bool useMainThread; // 0x1D
			public int customThreadAmount; // 0x20
			public bool showStats; // 0x24

			// Constructors
			public JobSettings(); // 0x003DDE40-0x003DDE60

			// Methods
			public void CopySettings(JobSettings source); // 0x003DDE00-0x003DDE40
		}

		public enum CombineJobMode // TypeDefIndex: 3025
		{
			CombineAtOnce = 0,
			CombinePerFrame = 1
		}

		public enum ThreadAmountMode // TypeDefIndex: 3026
		{
			AllThreads = 0,
			HalfThreads = 1,
			Custom = 2
		}

		public enum ThreadState // TypeDefIndex: 3027
		{
			isFree = 0,
			isReady = 1,
			isRunning = 2,
			hasError = 3
		}

		public class MeshCombineJobsThread // TypeDefIndex: 3028
		{
			// Fields
			public int threadId; // 0x10
			public ThreadState threadState; // 0x14
			public Queue<MeshCombineJob> meshCombineJobs; // 0x18
			public Queue<NewMeshObject> newMeshObjectsDone; // 0x20

			// Constructors
			public MeshCombineJobsThread(int threadId); // 0x003DDF20-0x003DDFA0

			// Methods
			public void ExecuteJobsThread(object state); // 0x003DDFA0-0x003DE6A0
		}

		public class MeshCombineJob // TypeDefIndex: 3029
		{
			// Fields
			public MeshCombiner meshCombiner; // 0x10
			public MeshObjectsHolder meshObjectsHolder; // 0x18
			public Transform parent; // 0x20
			public Vector3 position; // 0x28
			public int startIndex; // 0x34
			public int endIndex; // 0x38
			public bool firstMesh; // 0x3C
			public bool intersectsSurface; // 0x3D
			public int backFaceTrianglesRemoved; // 0x40
			public int trianglesRemoved; // 0x44
			public bool abort; // 0x48
			public string name; // 0x50

			// Constructors
			public MeshCombineJob(MeshCombiner meshCombiner, MeshObjectsHolder meshObjectsHolder, Transform parent, Vector3 position, int startIndex, int length, bool firstMesh, bool intersectsSurface); // 0x003DDE60-0x003DDF20
		}

		public class NewMeshObject // TypeDefIndex: 3030
		{
			// Fields
			public MeshCombineJob meshCombineJob; // 0x10
			public MeshCache.SubMeshCache newMeshCache; // 0x18
			public bool allSkipped; // 0x20
			public Vector3 newPosition; // 0x24
			private byte[] vertexIsBelow; // 0x30
			private const byte belowSurface = 1; // Metadata: 0x0015ADB9
			private const byte aboveSurface = 2; // Metadata: 0x0015ADBA

			// Constructors
			public NewMeshObject(); // 0x003DE6A0-0x003DE730

			// Methods
			public void Combine(MeshCombineJob meshCombineJob); // 0x003DE730-0x003DFFC0
			private void HasArray<T>(ref bool hasNewArray, bool hasArray, ref T[] newArray, Array array, int vertexCount, int totalVertices, bool useDefaultValue = false /* Metadata: 0x0015ADB8 */, T defaultValue = default);
			private void FillArray<T>(T[] array, int offset, int length, T value);
			public void RemoveTrianglesBelowSurface(Transform t, MeshCombineJob meshCombineJob); // 0x003E0BA0-0x003E1560
			public void RemoveBackFaceTriangles(); // 0x003DFFC0-0x003E0BA0
			private void ArrangeTriangles(); // 0x003E1560-0x003E1640
			public void CreateMesh(); // 0x003E1640-0x003E23F0
		}

		// Constructors
		public MeshCombineJobManager(); // 0x00375C20-0x00375EC0

		// Methods
		public static MeshCombineJobManager CreateInstance(MeshCombiner meshCombiner, GameObject instantiatePrefab); // 0x00373750-0x003739D0
		public static void ResetMeshCache(); // 0x00373BB0-0x00373C40
		private void Awake(); // 0x00373C40-0x00373C80
		private void OnEnable(); // 0x00373C80-0x00373D50
		public void Init(); // 0x00373D50-0x00373F20
		private void OnDestroy(); // 0x00373F20-0x00373F60
		private void Update(); // 0x00374530-0x00374580
		private void MyUpdate(); // 0x003751C0-0x003751D0
		public void SetJobMode(JobSettings newJobSettings); // 0x003739D0-0x00373BB0
		public void AddJob(MeshCombiner meshCombiner, MeshObjectsHolder meshObjectsHolder, Transform parent, Vector3 position); // 0x003751D0-0x003756C0
		private void EnqueueJob(MeshCombiner meshCombiner, MeshCombineJob meshCombineJob); // 0x003756C0-0x00375740
		public int MeshIntersectsSurface(MeshCombiner meshCombiner, CachedGameObject cachedGO); // 0x00375740-0x00375B60
		public void AbortJobs(); // 0x00373F60-0x00374530
		public void ExecuteJobs(); // 0x00374580-0x00374C70
		public void CombineMeshesDone(MeshCombineJobsThread meshCombineJobThread); // 0x00374C70-0x00374FE0
	}

	public class MeshCache // TypeDefIndex: 3031
	{
		// Fields
		public Mesh mesh; // 0x10
		public SubMeshCache[] subMeshCache; // 0x18
		public int subMeshCount; // 0x20

		// Nested types
		public class SubMeshCache // TypeDefIndex: 3032
		{
			// Fields
			public Vector3[] vertices; // 0x10
			public Vector3[] normals; // 0x18
			public Vector4[] tangents; // 0x20
			public Vector2[] uv; // 0x28
			public Vector2[] uv2; // 0x30
			public Vector2[] uv3; // 0x38
			public Vector2[] uv4; // 0x40
			public Color32[] colors32; // 0x48
			public int[] triangles; // 0x50
			public bool hasNormals; // 0x58
			public bool hasTangents; // 0x59
			public bool hasUv; // 0x5A
			public bool hasUv2; // 0x5B
			public bool hasUv3; // 0x5C
			public bool hasUv4; // 0x5D
			public bool hasColors; // 0x5E
			public int vertexCount; // 0x60
			public int triangleCount; // 0x64

			// Constructors
			public SubMeshCache(); // 0x003DD140-0x003DD150
			public SubMeshCache(Mesh mesh, int subMeshIndex); // 0x003DD460-0x003DD490
			public SubMeshCache(Mesh mesh, bool assignTriangles); // 0x003DD490-0x003DD830

			// Methods
			public void CopySubMeshCache(SubMeshCache source); // 0x003DD150-0x003DD460
			public void CopyArray<T>(Array sourceArray, ref T[] destinationArray, int vertexCount);
			public void CheckHasArrays(); // 0x003DD830-0x003DD8C0
			public void ResetHasBooleans(); // 0x003DD8C0-0x003DD8E0
			public void Init(bool initTriangles = true /* Metadata: 0x0015ADBB */); // 0x003DD8E0-0x003DD940
			public void RebuildVertexBuffer(SubMeshCache sub, bool resizeArrays); // 0x003DD940-0x003DDE00
		}

		// Constructors
		public MeshCache(Mesh mesh); // 0x00373470-0x00373750
	}

	[ExecuteInEditMode] // 0x00254CA0-0x00254CB0
	public class MeshCombiner : MonoBehaviour // TypeDefIndex: 3033
	{
		// Fields
		public static List<MeshCombiner> instances; // 0x00
		private DefaultMethod OnCombiningReady; // 0x18
		public MeshCombineJobManager.JobSettings jobSettings; // 0x20
		public LODGroupSettings[] lodGroupsSettings; // 0x28
		public ComputeShader computeDepthToArray; // 0x30
		public GameObject instantiatePrefab; // 0x38
		public const int maxLodCount = 8; // Metadata: 0x0015ADC0
		public string saveMeshesFolder; // 0x40
		public ObjectOctree.Cell octree; // 0x48
		public List<ObjectOctree.MaxCell> changedCells; // 0x50
		[NonSerialized]
		public bool octreeContainsObjects; // 0x58
		public bool useCells; // 0x59
		public int cellSize; // 0x5C
		public Vector3 cellOffset; // 0x60
		public bool useVertexOutputLimit; // 0x6C
		public int vertexOutputLimit; // 0x70
		public RebakeLightingMode rebakeLightingMode; // 0x74
		public bool copyBakedLighting; // 0x78
		public bool validCopyBakedLighting; // 0x79
		public bool rebakeLighting; // 0x7A
		public bool validRebakeLighting; // 0x7B
		public LightProbeUsage lightProbeUsage; // 0x7C
		public ReflectionProbeUsage reflectionProbeUsage; // 0x80
		public MotionVectorGenerationMode motionVectorGenerationMode; // 0x84
		public bool receiveShadows; // 0x88
		public ShadowCastingMode shadowCastingMode; // 0x8C
		public int outputLayer; // 0x90
		public int outputStatic; // 0x94
		public float scaleInLightmap; // 0x98
		public bool addMeshColliders; // 0x9C
		public bool addMeshCollidersInRange; // 0x9D
		public Bounds addMeshCollidersBounds; // 0xA0
		public bool makeMeshesUnreadable; // 0xB8
		public bool removeTrianglesBelowSurface; // 0xB9
		public bool noColliders; // 0xBA
		public LayerMask surfaceLayerMask; // 0xBC
		public float maxSurfaceHeight; // 0xC0
		public bool removeOverlappingTriangles; // 0xC4
		public GameObject overlappingCollidersGO; // 0xC8
		public LayerMask overlapLayerMask; // 0xD0
		public int voxelizeLayer; // 0xD4
		public int lodGroupLayer; // 0xD8
		public bool removeBackFaceTriangles; // 0xDC
		public BackFaceTriangleMode backFaceTriangleMode; // 0xE0
		public Vector3 backFaceDirection; // 0xE4
		public Bounds backFaceBounds; // 0xF0
		public bool twoSidedShadows; // 0x108
		public bool combineInRuntime; // 0x109
		public bool combineOnStart; // 0x10A
		public bool useCombineSwapKey; // 0x10B
		public KeyCode combineSwapKey; // 0x10C
		public HandleComponent originalMeshRenderers; // 0x110
		public HandleComponent originalLODGroups; // 0x114
		public SearchOptions searchOptions; // 0x118
		public Vector3 oldPosition; // 0x120
		public Vector3 oldScale; // 0x12C
		public LodParentHolder[] lodParentHolders; // 0x138
		public List<CachedGameObject> foundObjects; // 0x140
		public List<CachedLodGameObject> foundLodObjects; // 0x148
		public List<LODGroup> foundLodGroups; // 0x150
		public List<Collider> foundColliders; // 0x158
		public HashSet<LODGroup> uniqueFoundLodGroups; // 0x160
		public List<Mesh> unreadableMeshes; // 0x168
		public HashSet<Mesh> selectImportSettingsMeshes; // 0x170
		public HashSet<MeshCombineJobManager.MeshCombineJob> meshCombineJobs; // 0x178
		public int totalMeshCombineJobs; // 0x180
		public int mrDisabledCount; // 0x184
		public bool combined; // 0x188
		public bool activeOriginal; // 0x189
		public bool combinedActive; // 0x18A
		public bool drawGizmos; // 0x18B
		public bool drawMeshBounds; // 0x18C
		public int originalTotalVertices; // 0x190
		public int originalTotalTriangles; // 0x194
		public int totalVertices; // 0x198
		public int totalTriangles; // 0x19C
		public int originalDrawCalls; // 0x1A0
		public int newDrawCalls; // 0x1A4
		public int foundMaterialsCount; // 0x1A8
		public float combineTime; // 0x1AC
		public FastList<MeshColliderAdd> addMeshCollidersList; // 0x1B0
		private HashSet<Transform> uniqueLodObjects; // 0x1B8
		private HashSet<Material> foundMaterials; // 0x1C0
		[NonSerialized]
		private MeshCombiner thisInstance; // 0x1C8
		private bool hasFoundFirstObject; // 0x1D0
		private Bounds bounds; // 0x1D4
		private Stopwatch stopwatch; // 0x1F0

		// Events
		public event DefaultMethod OnCombiningReady {{
			add; // 0x00375EC0-0x00375F50
			remove; // 0x00375F50-0x00375FE0
		}

		// Nested types
		public enum ObjectType // TypeDefIndex: 3034
		{
			Normal = 0,
			LodGroup = 1,
			LodRenderer = 2
		}

		public enum HandleComponent // TypeDefIndex: 3035
		{
			Disable = 0,
			Destroy = 1
		}

		public enum ObjectCenter // TypeDefIndex: 3036
		{
			BoundsCenter = 0,
			TransformPosition = 1
		}

		public enum BackFaceTriangleMode // TypeDefIndex: 3037
		{
			Box = 0,
			Direction = 1
		}

		public delegate void DefaultMethod(); // TypeDefIndex: 3038; 0x003E26A0-0x003E28E0

		public enum RebakeLightingMode // TypeDefIndex: 3039
		{
			CopyLightmapUvs = 0,
			RegenarateLightmapUvs = 1
		}

		[Serializable]
		public class SearchOptions // TypeDefIndex: 3040
		{
			// Fields
			public GameObject parent; // 0x10
			public ObjectCenter objectCenter; // 0x18
			public LODGroupSearchMode lodGroupSearchMode; // 0x1C
			public bool useSearchBox; // 0x20
			public Bounds searchBoxBounds; // 0x24
			public bool searchBoxSquare; // 0x3C
			public Vector3 searchBoxPivot; // 0x40
			public Vector3 searchBoxSize; // 0x4C
			public bool useMaxBoundsFactor; // 0x58
			public float maxBoundsFactor; // 0x5C
			public bool useVertexInputLimit; // 0x60
			public int vertexInputLimit; // 0x64
			public bool useLayerMask; // 0x68
			public LayerMask layerMask; // 0x6C
			public bool useTag; // 0x70
			public string tag; // 0x78
			public bool useNameContains; // 0x80
			public List<string> nameContainList; // 0x88
			public bool onlyActive; // 0x90
			public bool onlyStatic; // 0x91
			public bool useComponentsFilter; // 0x92
			public ComponentCondition componentCondition; // 0x94
			public List<string> componentNameList; // 0x98

			// Nested types
			public enum ComponentCondition // TypeDefIndex: 3041
			{
				And = 0,
				Or = 1,
				Not = 2
			}

			public enum LODGroupSearchMode // TypeDefIndex: 3042
			{
				LodGroup = 0,
				LodRenderers = 1
			}

			// Methods
			public void GetSearchBoxBounds(); // 0x003E2D00-0x003E2E60
		}

		[Serializable]
		public class LODGroupSettings // TypeDefIndex: 3043
		{
			// Fields
			public LODSettings[] lodSettings; // 0x10

			// Constructors
			public LODGroupSettings(int lodParentIndex); // 0x003E2910-0x003E2AA0
		}

		[Serializable]
		public class LODSettings // TypeDefIndex: 3044
		{
			// Fields
			public float screenRelativeTransitionHeight; // 0x10
			public float fadeTransitionWidth; // 0x14

			// Constructors
			public LODSettings(float screenRelativeTransitionHeight); // 0x003E2AA0-0x003E2AB0
		}

		public class LodParentHolder // TypeDefIndex: 3045
		{
			// Fields
			public GameObject go; // 0x10
			public Transform t; // 0x18
			public bool found; // 0x20
			public int[] lods; // 0x28

			// Constructors
			public LodParentHolder(int lodCount); // 0x003E2AB0-0x003E2AF0

			// Methods
			public void Create(MeshCombiner meshCombiner, int lodParentIndex); // 0x003E2AF0-0x003E2CE0
			public void Reset(); // 0x003E2CE0-0x003E2D00
		}

		// Constructors
		public MeshCombiner(); // 0x0037C200-0x0037C5F0
		static MeshCombiner(); // 0x0037C5F0-0x0037CD30

		// Methods
		public void AddMeshColliders(); // 0x00374FE0-0x00375100
		public void ExecuteOnCombiningReady(); // 0x00375100-0x003751C0
		private void Awake(); // 0x00375FE0-0x00376050
		private void OnEnable(); // 0x00376050-0x00376190
		private void Start(); // 0x00376190-0x00376410
		private void OnDestroy(); // 0x0037AD10-0x0037AF60
		public static MeshCombiner GetInstance(string name); // 0x0037AF90-0x0037B140
		public void CopyJobSettingsToAllInstances(); // 0x0037B140-0x0037B260
		public void InitMeshCombineJobManager(); // 0x0037AC00-0x0037AD10
		public void CreateLodGroupsSettings(); // 0x0037B260-0x0037B3A0
		private void StartRuntime(); // 0x00376410-0x003765D0
		public void DestroyCombinedObjects(); // 0x0037B3A0-0x0037B430
		private void Reset(); // 0x003776B0-0x00377A60
		public void AbortAndClearMeshCombineJobs(); // 0x0037A900-0x0037AA70
		public void ClearMeshCombineJobs(); // 0x00375B60-0x00375C20
		public void AddObjects(List<Transform> transforms, bool useSearchOptions, bool checkForLODGroups = true /* Metadata: 0x0015ADBC */); // 0x0037B480-0x0037B850
		public void AddObjectsAutomatically(); // 0x00376A00-0x00376B40
		public void AddFoundObjectsToOctree(); // 0x00377DC0-0x00378120
		private void AddFoundMaterials(MeshRenderer mr); // 0x00378760-0x003788A0
		public void ResetOctree(); // 0x0037B430-0x0037B480
		public void CalcOctreeSize(Bounds bounds); // 0x00378340-0x00378760
		public void ApplyChanges(); // 0x0037B850-0x0037B940
		public void CombineAll(); // 0x003765D0-0x00376A00
		private void InitAndResetLodParentsCount(); // 0x0037AA70-0x0037AC00
		public void AddObjectsFromSearchParent(); // 0x00377A60-0x00377DC0
		private void AddLodGroups(LODGroup[] lodGroups, bool useSearchOptions = true /* Metadata: 0x0015ADBD */); // 0x003788A0-0x00379350
		private void AddTransforms(Transform[] transforms, bool useSearchOptions = true /* Metadata: 0x0015ADBE */); // 0x00379350-0x003799B0
		private int ValidObject(Transform t, ObjectType objectType, bool useSearchOptions, ref CachedGameObject cachedGameObject); // 0x003799B0-0x0037A900
		public void RestoreOriginalRenderersAndLODGroups(); // 0x0037AF60-0x0037AF90
		public void SwapCombine(); // 0x0037B940-0x0037B980
		private void SetOriginalCollidersActive(bool active); // 0x00376B40-0x00376CD0
		public void ExecuteHandleObjects(bool active, HandleComponent handleOriginalObjects, HandleComponent handleOriginalLodGroups, bool includeColliders = true /* Metadata: 0x0015ADBF */); // 0x00376CD0-0x003776B0
		private void DrawGizmosCube(Bounds bounds, Color color); // 0x0037B980-0x0037BBE0
		private void OnDrawGizmosSelected(); // 0x0037BBE0-0x0037C200
		private void LogOctreeInfo(); // 0x00378120-0x00378340
	}

	public struct MeshColliderAdd // TypeDefIndex: 3046
	{
		// Fields
		public GameObject go; // 0x00
		public Mesh mesh; // 0x08

		// Constructors
		public MeshColliderAdd(GameObject go, Mesh mesh); // 0x00229590-0x002295B0
	}

	[ExecuteInEditMode] // 0x00254CB0-0x00254CC0
	public class ObjectSpawner : MonoBehaviour // TypeDefIndex: 3047
	{
		// Fields
		public GameObject[] objects; // 0x18
		public float density; // 0x20
		public Vector2 scaleRange; // 0x24
		public Vector3 rotationRange; // 0x2C
		public Vector2 heightRange; // 0x38
		public float scaleMulti; // 0x40
		public float resolutionPerMeter; // 0x44
		public bool spawnInRuntime; // 0x48
		public bool spawn; // 0x49
		public bool deleteChildren; // 0x4A
		private Transform t; // 0x50

		// Constructors
		public ObjectSpawner(); // 0x003AF7F0-0x003AFD50

		// Methods
		private void Awake(); // 0x003AE680-0x003AE710
		private void Update(); // 0x003AF260-0x003AF290
		public void DeleteChildren(); // 0x003AF290-0x003AF540
		public void Spawn(); // 0x003AE710-0x003AF260
		private void OnDrawGizmosSelected(); // 0x003AF540-0x003AF7F0
	}

	public class RemoveGeometryBelowTerrain : MonoBehaviour // TypeDefIndex: 3048
	{
		// Fields
		private int totalTriangles; // 0x18
		private int removeTriangles; // 0x1C
		private int skippedObjects; // 0x20
		public List<Transform> terrains; // 0x28
		public List<Transform> meshTerrains; // 0x30
		public Bounds[] terrainBounds; // 0x38
		public Bounds[] meshBounds; // 0x40
		private Terrain[] terrainComponents; // 0x48
		private Terrain[] terrainArray; // 0x50
		private Bounds[] terrainBoundsArray; // 0x58
		private MeshRenderer[] mrs; // 0x60
		private Mesh[] meshTerrainComponents; // 0x68
		private Mesh[] meshArray; // 0x70
		public bool runOnStart; // 0x78

		// Constructors
		public RemoveGeometryBelowTerrain(); // 0x003BADE0-0x003BAE90

		// Methods
		private void Start(); // 0x003B8830-0x003B8890
		public void Remove(GameObject go); // 0x003B8890-0x003B8E70
		public void RemoveMesh(Transform t, Mesh mesh); // 0x003B8E70-0x003B9170
		public bool IsMeshUnderTerrain(Transform t, Mesh mesh); // 0x003B9170-0x003B9340
		public void GetTerrainComponents(); // 0x003B9930-0x003B9AA0
		public void GetMeshRenderersAndComponents(); // 0x003B9AA0-0x003B9D50
		public void CreateTerrainBounds(); // 0x003B9D50-0x003BA490
		public void MakeIntersectLists(Bounds bounds); // 0x003BA490-0x003BAC00
		public int InterectTerrain(Vector3 pos); // 0x003BAC00-0x003BACF0
		public int InterectMesh(Vector3 pos); // 0x003BACF0-0x003BADE0
		public float GetTerrainHeight(Vector3 pos); // 0x003B97B0-0x003B9930
		public void RemoveTriangles(Transform t, List<int> newTriangles, Vector3[] vertices); // 0x003B9340-0x003B97B0
	}

	public class SwapCombineKey : MonoBehaviour // TypeDefIndex: 3049
	{
		// Fields
		public static SwapCombineKey instance; // 0x00
		public List<MeshCombiner> meshCombinerList; // 0x18
		private MeshCombiner meshCombiner; // 0x20
		private GUIStyle textStyle; // 0x28

		// Constructors
		public SwapCombineKey(); // 0x003D4870-0x003D4900

		// Methods
		private void Awake(); // 0x003D4350-0x003D43C0
		private void OnDestroy(); // 0x003D43C0-0x003D4400
		private void Update(); // 0x003D4400-0x003D44D0
		private void OnGUI(); // 0x003D44D0-0x003D4870
	}

	public class CachedComponents : MonoBehaviour // TypeDefIndex: 3050
	{
		// Fields
		public GameObject go; // 0x18
		public Transform t; // 0x20
		public MeshRenderer mr; // 0x28
		public MeshFilter mf; // 0x30
		public GarbageCollectMesh garbageCollectMesh; // 0x38

		// Constructors
		public CachedComponents(); // 0x004084E0-0x00408520
	}

	public class Console : MonoBehaviour // TypeDefIndex: 3051
	{
		// Fields
		public static Console instance; // 0x00
		public KeyCode consoleKey; // 0x18
		public bool logActive; // 0x1C
		public bool showConsole; // 0x1D
		public bool showOnError; // 0x1E
		public bool combineAutomatic; // 0x1F
		private bool showLast; // 0x20
		private bool setFocus; // 0x21
		private GameObject selectGO; // 0x28
		public List<LogEntry> logs; // 0x30
		private Rect window; // 0x38
		private Rect inputRect; // 0x48
		private Rect logRect; // 0x58
		private Rect vScrollRect; // 0x68
		private string inputText; // 0x78
		private float scrollPos; // 0x80
		private int lines; // 0x84
		private bool showUnityLog; // 0x88
		private bool showInputLog; // 0x89
		private MeshCombiner[] meshCombiners; // 0x90
		private MeshCombiner selectedMeshCombiner; // 0x98

		// Nested types
		public class LogEntry // TypeDefIndex: 3052
		{
			// Fields
			public string logString; // 0x10
			public string stackTrace; // 0x18
			public LogType logType; // 0x20
			public int commandType; // 0x24
			public bool unityLog; // 0x28
			public float tStamp; // 0x2C
			public GameObject go; // 0x30
			public MeshCombiner meshCombiner; // 0x38

			// Constructors
			public LogEntry(string logString, string stackTrace, LogType logType, bool unityLog = false /* Metadata: 0x0015AE0C */, int commandType = 0 /* Metadata: 0x0015AE0D */, GameObject go = null, MeshCombiner meshCombiner = null); // 0x003D9C80-0x003D9CA0
		}

		// Constructors
		public Console(); // 0x004315B0-0x00431660

		// Methods
		private void Awake(); // 0x004299F0-0x00429A90
		private void ReportStartup(); // 0x00429A90-0x00429BA0
		private void FindMeshCombiners(); // 0x0042A740-0x0042A7A0
		private void ReportMeshCombiners(bool reportSelected = true /* Metadata: 0x0015AE04 */); // 0x00429C40-0x00429DD0
		private void ReportMeshCombiner(MeshCombiner meshCombiner, bool foundText = false /* Metadata: 0x0015AE05 */); // 0x0042A190-0x0042A740
		public int SelectMeshCombiner(string name); // 0x00429DD0-0x0042A190
		private void OnEnable(); // 0x0042A7A0-0x0042A7F0
		private void OnDisable(); // 0x0042A7F0-0x0042A8B0
		private void OnDestroy(); // 0x0042A8B0-0x0042A8F0
		public static void Log(string logString, int commandType = 0 /* Metadata: 0x0015AE06 */, GameObject go = null, MeshCombiner meshCombiner = null); // 0x00429BA0-0x00429C40
		private void HandleLog(string logString, string stackTrace, LogType logType); // 0x0042A8F0-0x0042A9A0
		private void Update(); // 0x0042A9B0-0x0042AA20
		private void SetConsoleActive(bool active); // 0x0042A9A0-0x0042A9B0
		private void ExecuteCommand(string cmd); // 0x0042AA20-0x0042C570
		private void DirSort(); // 0x00430330-0x00430370
		private void DirSort(string name); // 0x0042EE40-0x0042EFF0
		public void SortLog(GameObject[] gos, bool showMeshInfo = false /* Metadata: 0x0015AE0A */); // 0x0042EFF0-0x0042F950
		private string GetMeshInfo(GameObject go, ref int meshCount); // 0x0042F950-0x0042FF80
		private void TimeStep(string cmd); // 0x00430370-0x004303F0
		private void TimeScale(string cmd); // 0x004303F0-0x00430470
		private void Clear(LogEntry log, string cmd); // 0x0042E470-0x0042E5D0
		private void DirAll(); // 0x0042E700-0x0042EE40
		private void Dir(); // 0x0042C570-0x0042D540
		private void Components(LogEntry log); // 0x0042D540-0x0042D7F0
		private void ShowPath(bool showLines = true /* Metadata: 0x0015AE0B */); // 0x004302A0-0x00430330
		private string GetPath(GameObject go); // 0x0042FF80-0x004302A0
		private void CD(LogEntry log, string name); // 0x0042D7F0-0x0042DD40
		public void SetActiveContains(string textContains, bool active); // 0x0042DD40-0x0042E470
		public void DirContains(string textContains); // 0x0042E5D0-0x0042E700
		private void OnGUI(); // 0x00430470-0x00431410
		private void AnimateColor(Color col, LogEntry log, float multi); // 0x00431410-0x004315B0
	}

	public class DirectDraw : MonoBehaviour // TypeDefIndex: 3053
	{
		// Fields
		private MeshRenderer[] mrs; // 0x18
		private Mesh[] meshes; // 0x20
		private Material[] mats; // 0x28
		private Vector3[] positions; // 0x30
		private Quaternion[] rotations; // 0x38

		// Constructors
		public DirectDraw(); // 0x00359B60-0x00359BA0

		// Methods
		private void Awake(); // 0x00359370-0x00359930
		private void SetMeshRenderersEnabled(bool enabled); // 0x00359930-0x003599E0
		private void Update(); // 0x003599E0-0x00359B60
	}

	public class DisabledLodMeshRender : MonoBehaviour // TypeDefIndex: 3054
	{
		// Fields
		public MeshCombiner meshCombiner; // 0x18
		public CachedLodGameObject cachedLodGO; // 0x20

		// Constructors
		public DisabledLodMeshRender(); // 0x00359CC0-0x00359D00
	}

	public class DisabledMeshRenderer : MonoBehaviour // TypeDefIndex: 3055
	{
		// Fields
		public MeshCombiner meshCombiner; // 0x18
		public CachedGameObject cachedGO; // 0x20

		// Constructors
		public DisabledMeshRenderer(); // 0x00359D00-0x00359D40
	}

	public class FastListBase // TypeDefIndex: 3056
	{
		// Fields
		protected const int defaultCapacity = 4; // Metadata: 0x0015AE11
		public int Count; // 0x10
		protected int _count; // 0x14
		protected int arraySize; // 0x18

		// Constructors
		public FastListBase(); // 0x0035F6D0-0x0035F6E0
	}

	public class FastListBase<T> : FastListBase // TypeDefIndex: 3057
	{
		// Fields
		public T[] items;

		// Constructors
		public FastListBase();

		// Methods
		protected void DoubleCapacity();
	}

	[Serializable]
	public class FastList<T> : FastListBase<T> // TypeDefIndex: 3058
	{
		// Constructors
		public FastList();
		public FastList(int capacity);

		// Methods
		protected void SetCapacity(int capacity);
		public void SetCount(int count);
		public virtual int Add(T item);
		public virtual void AddRange(T[] arrayItems);
		public virtual void RemoveAt(int index);
		public virtual void RemoveLast();
		public virtual T Dequeue();
		public virtual void Clear();
		public virtual T[] ToArray();
	}

	[ExecuteInEditMode] // 0x00254CC0-0x00254CD0
	public class GarbageCollectMesh : MonoBehaviour // TypeDefIndex: 3059
	{
		// Fields
		public Mesh mesh; // 0x18

		// Constructors
		public GarbageCollectMesh(); // 0x003649C0-0x00364A00

		// Methods
		private void OnDestroy(); // 0x003648A0-0x003649C0
	}

	public class MCS_CameraController : MonoBehaviour // TypeDefIndex: 3060
	{
		// Fields
		public float speed; // 0x18
		public float mouseMoveSpeed; // 0x1C
		public float shiftMulti; // 0x20
		public float controlMulti; // 0x24
		private Vector3 oldMousePosition; // 0x28
		private GameObject cameraMountGO; // 0x38
		private GameObject cameraChildGO; // 0x40
		private Transform cameraMountT; // 0x48
		private Transform cameraChildT; // 0x50
		private Transform t; // 0x58

		// Constructors
		public MCS_CameraController(); // 0x0036CC30-0x0036CC80

		// Methods
		private void Awake(); // 0x0036BFA0-0x0036BFF0
		private void CreateParents(); // 0x0036BFF0-0x0036C2D0
		private void Update(); // 0x0036C2D0-0x0036CC30
	}

	public class MCS_FPSCounter : MonoBehaviour // TypeDefIndex: 3061
	{
		// Fields
		public static MCS_FPSCounter instance; // 0x00
		public float interval; // 0x18
		public GUIType displayType; // 0x1C
		public Vector2 gradientRange; // 0x20
		public Font fontRun; // 0x28
		public Font fontResult; // 0x30
		public Texture logo; // 0x38
		public bool showLogoOnResultsScreen; // 0x40
		public KeyCode showHideButton; // 0x44
		public bool acceptInput; // 0x48
		public bool reset; // 0x49
		public float currentFPS; // 0x4C
		public float averageFPS; // 0x50
		public float minimumFPS; // 0x54
		public float maximumFPS; // 0x58
		private int totalFrameCount; // 0x5C
		private int tempFrameCount; // 0x60
		private double tStamp; // 0x68
		private double tStampTemp; // 0x70
		private string currentFPSText; // 0x78
		private string avgFPSText; // 0x80
		private string minFPSText; // 0x88
		private string maxFSPText; // 0x90
		private GUIStyle bigStyle; // 0x98
		private GUIStyle bigStyleShadow; // 0xA0
		private GUIStyle smallStyle; // 0xA8
		private GUIStyle smallStyleShadow; // 0xB0
		private GUIStyle smallStyleLabel; // 0xB8
		private GUIStyle headerStyle; // 0xC0
		private Rect[] rectsRun; // 0xC8
		private Rect[] rectsResult; // 0xD0
		private Gradient gradient; // 0xD8
		private const float line1 = 4f; // Metadata: 0x0015AE15
		private const float line2 = 30f; // Metadata: 0x0015AE19
		private const float line3 = 44f; // Metadata: 0x0015AE1D
		private const float line4 = 58f; // Metadata: 0x0015AE21
		private const float labelWidth = 26f; // Metadata: 0x0015AE25
		private const float paddingH = 8f; // Metadata: 0x0015AE29
		private const float lineHeight = 22f; // Metadata: 0x0015AE2D
		private float columnRight; // 0xE0
		private float columnLeft; // 0xE4
		private Color fontShadow; // 0xE8
		private Color label; // 0xF8
		private Color colorCurrent; // 0x108
		private Color colorAvg; // 0x118
		private const string resultHeader = "BENCHMARK RESULTS"; // Metadata: 0x0015AE31
		private const string resultLabelAvg = "AVERAGE FPS:"; // Metadata: 0x0015AE46
		private const string resultLabelMin = "MINIMUM FPS:"; // Metadata: 0x0015AE56
		private const string resultLabelMax = "MAXIMUM FPS:"; // Metadata: 0x0015AE66
		private GUIContent resultHeaderGUI; // 0x128
		private GUIContent reslutLabelAvgGUI; // 0x130
		private GUIContent avgTextGUI; // 0x138
		private GUIContent instructions; // 0x140
		private const string runLabelAvg = "Avg:"; // Metadata: 0x0015AE76
		private const string runLabelMin = "Min:"; // Metadata: 0x0015AE7E
		private const string runLabelMax = "Max:"; // Metadata: 0x0015AE86
		private Vector2 screenSize; // 0x148
		private GUIType oldDisplayType; // 0x150

		// Nested types
		public enum GUIType // TypeDefIndex: 3062
		{
			DisplayRunning = 0,
			DisplayResults = 1,
			DisplayNothing = 2
		}

		// Constructors
		public MCS_FPSCounter(); // 0x0036F580-0x0036F8E0

		// Methods
		private void Awake(); // 0x0036CC80-0x0036CD90
		private void OnDestroy(); // 0x0036CD90-0x0036CE50
		private void OnGUI(); // 0x0036CE50-0x0036D790
		private void SetRectsRun(); // 0x0036D790-0x0036DAF0
		private void SetRectsResult(); // 0x0036DAF0-0x0036E3E0
		private void Start(); // 0x0036E3E0-0x0036E980
		private void Update(); // 0x0036E980-0x0036ECF0
		public void StartBenchmark(); // 0x0036F350-0x0036F3F0
		public void StopBenchmark(); // 0x0036F3F0-0x0036F580
		private void GetFPS(); // 0x0036ECF0-0x0036F1A0
		public void Reset(); // 0x0036F2C0-0x0036F350
		private Color EvaluateGradient(float f); // 0x0036F1A0-0x0036F2C0
	}

	public struct AABB3 // TypeDefIndex: 3063
	{
		// Fields
		public Vector3 min; // 0x00
		public Vector3 max; // 0x0C

		// Constructors
		public AABB3(Vector3 min, Vector3 max); // 0x00256D40-0x00256D60
	}

	public struct Triangle3 // TypeDefIndex: 3064
	{
		// Fields
		public Vector3 a; // 0x00
		public Vector3 b; // 0x0C
		public Vector3 c; // 0x18
		public Vector3 dirAb; // 0x24
		public Vector3 dirAc; // 0x30
		public Vector3 dirBc; // 0x3C
		public Vector3 h1; // 0x48
		public float ab; // 0x54
		public float ac; // 0x58
		public float bc; // 0x5C
		public float area; // 0x60
		public float h; // 0x64
		public float ah; // 0x68
		public float hb; // 0x6C
	}

	public struct Sphere3 // TypeDefIndex: 3065
	{
		// Fields
		public Vector3 center; // 0x00
		public float radius; // 0x0C
	}

	public struct Int2 // TypeDefIndex: 3066
	{
		// Fields
		public int x; // 0x00
		public int y; // 0x04

		// Constructors
		public Int2(int x, int y); // 0x00229530-0x00229590
	}

	public static class Mathw // TypeDefIndex: 3067
	{
		// Fields
		public static readonly int[] bits; // 0x00

		// Constructors
		static Mathw(); // 0x00372E80-0x00372F30

		// Methods
		public static float GetMax(Vector3 v); // 0x00372C90-0x00372CB0
		public static Vector3 Snap(Vector3 v, float snapSize); // 0x00372CB0-0x00372DA0
		public static Vector3 Abs(Vector3 v); // 0x00372DA0-0x00372DE0
		public static bool IntersectAABB3Sphere3(AABB3 box, Sphere3 sphere); // 0x00372DE0-0x00372E80
	}

	public static class Methods // TypeDefIndex: 3068
	{
		// Methods
		public static bool LayerMaskContainsLayer(int layerMask, int layer); // 0x003A65D0-0x003A65E0
		public static int GetFirstLayerInLayerMask(int layerMask); // 0x003A65E0-0x003A6680
		public static bool Contains(string compare, string name); // 0x003A6680-0x003A6810
		public static T[] Search<T>(GameObject parentGO = null);
		public static FastList<GameObject> GetAllRootGameObjects(); // 0x003A6810-0x003A69C0
		public static T[] SearchParent<T>(GameObject parentGO, bool searchInActiveGameObjects)
			where T : Component;
		public static FastList<T> SearchAllScenes<T>(bool searchInActiveGameObjects)
			where T : Component;
		public static T Find<T>(GameObject parentGO, string name)
			where T : Component;
		public static void DestroyChildren(Transform t); // 0x003A69C0-0x003A6B50
		public static void Destroy(GameObject go); // 0x003A6B50-0x003A6C50
		public static void SetChildrenActive(Transform t, bool active); // 0x003A6C50-0x003A6DD0
		public static void SnapBoundsAndPreserveArea(ref Bounds bounds, float snapSize, Vector3 offset); // 0x003A6DD0-0x003A70F0
		public static void ListRemoveAt<T>(List<T> list, int index);
	}

	public class ReadMe : MonoBehaviour // TypeDefIndex: 3069
	{
		// Fields
		public bool buttonEdit; // 0x18
		public string readme; // 0x20

		// Constructors
		public ReadMe(); // 0x003B87E0-0x003B8820
	}

	public class BaseOctree // TypeDefIndex: 3070
	{
		// Nested types
		public class Cell // TypeDefIndex: 3071
		{
			// Fields
			public Cell mainParent; // 0x10
			public Cell parent; // 0x18
			public bool[] cellsUsed; // 0x20
			public Bounds bounds; // 0x28
			public int cellIndex; // 0x40
			public int cellCount; // 0x44
			public int level; // 0x48
			public int maxLevels; // 0x4C

			// Constructors
			public Cell(); // 0x003D7BE0-0x003D7BF0
			public Cell(Vector3 position, Vector3 size, int maxLevels); // 0x003D7BF0-0x003D7CC0

			// Methods
			public void SetCell(Cell parent, int cellIndex, Bounds bounds); // 0x003D7CC0-0x003D7D00
			protected int AddCell<T, U>(ref T[] cells, Vector3 position, out bool maxCellCreated)
				where T : Cell, new()
				where U : Cell, new();
			protected void AddCell<T, U>(ref T[] cells, int index, int x, int y, int z, out bool maxCellCreated)
				where T : Cell, new()
				where U : Cell, new();
			public bool InsideBounds(Vector3 position); // 0x003D7D00-0x003D7FD0
			public void Reset(ref Cell[] cells); // 0x003D7FD0-0x003D7FE0
		}
	}

	public class ObjectOctree // TypeDefIndex: 3072
	{
		// Nested types
		public class LODParent // TypeDefIndex: 3073
		{
			// Fields
			public GameObject cellGO; // 0x10
			public Transform cellT; // 0x18
			public LODGroup lodGroup; // 0x20
			public LODLevel[] lodLevels; // 0x28
			public bool hasChanged; // 0x30
			public int jobsPending; // 0x34

			// Constructors
			public LODParent(int lodCount); // 0x003E3AF0-0x003E3CA0

			// Methods
			public void AssignLODGroup(MeshCombiner meshCombiner); // 0x003E23F0-0x003E2690
			public void ApplyChanges(MeshCombiner meshCombiner); // 0x003E59F0-0x003E5AF0
		}

		public class LODLevel // TypeDefIndex: 3074
		{
			// Fields
			public List<CachedGameObject> cachedGOs; // 0x10
			public List<MeshObjectsHolder> meshObjectsHolders; // 0x18
			public List<MeshObjectsHolder> changedMeshObjectsHolders; // 0x20
			public List<MeshRenderer> newMeshRenderers; // 0x28
			public int vertCount; // 0x30
			public int objectCount; // 0x34

			// Constructors
			public LODLevel(); // 0x003E5980-0x003E59F0

			// Methods
			public int GetSortMeshIndex(Material mat, bool shadowCastingModeTwoSided, int lightmapIndex); // 0x003E41F0-0x003E43B0
			public void ApplyChanges(MeshCombiner meshCombiner); // 0x003E58F0-0x003E5980
		}

		public class MaxCell : Cell // TypeDefIndex: 3075
		{
			// Fields
			public static int maxCellCount; // 0x00
			public LODParent[] lodParents; // 0x58
			public List<LODParent> changedLodParents; // 0x60
			public bool hasChanged; // 0x68

			// Constructors
			public MaxCell(); // 0x003E5B90-0x003E5BA0

			// Methods
			public void ApplyChanges(MeshCombiner meshCombiner); // 0x003E5AF0-0x003E5B90
		}

		public class Cell : BaseOctree.Cell // TypeDefIndex: 3076
		{
			// Fields
			public Cell[] cells; // 0x50

			// Constructors
			public Cell(); // 0x003E33E0-0x003E33F0

			// Methods
			public CachedGameObject AddObject(Vector3 position, MeshCombiner meshCombiner, CachedGameObject cachedGO, int lodParentIndex, int lodLevel, bool isChangeMode = false /* Metadata: 0x0015AE9A */); // 0x003E33F0-0x003E3710
			private void AddObjectInternal(MeshCombiner meshCombiner, CachedGameObject cachedGO, Vector3 position, int lodParentIndex, int lodLevel, bool isChangeMode); // 0x003E3710-0x003E3AF0
			public void SortObjects(MeshCombiner meshCombiner); // 0x003E43B0-0x003E4860
			public bool SortObject(MeshCombiner meshCombiner, LODLevel lod, CachedGameObject cachedGO, bool isChangeMode = false /* Metadata: 0x0015AE9B */); // 0x003E3CA0-0x003E41F0
			public void CombineMeshes(MeshCombiner meshCombiner, int lodParentIndex); // 0x003E4860-0x003E5060
			public void Draw(MeshCombiner meshCombiner, bool onlyMaxLevel, bool drawLevel0); // 0x003E5060-0x003E58F0
		}
	}

	[Serializable]
	public class MeshObjectsHolder // TypeDefIndex: 3077
	{
		// Fields
		public Material mat; // 0x10
		public List<MeshObject> meshObjects; // 0x18
		public ObjectOctree.LODParent lodParent; // 0x20
		public List<CachedGameObject> newCachedGOs; // 0x28
		public int lodLevel; // 0x30
		public int lightmapIndex; // 0x34
		public bool shadowCastingModeTwoSided; // 0x38
		public bool hasChanged; // 0x39

		// Constructors
		public MeshObjectsHolder(CachedGameObject cachedGO, Material mat, int subMeshIndex, bool shadowCastingModeTwoSided, int lightmapIndex); // 0x003A63A0-0x003A65D0
	}

	[Serializable]
	public class MeshObject // TypeDefIndex: 3078
	{
		// Fields
		public CachedGameObject cachedGO; // 0x10
		public MeshCache meshCache; // 0x18
		public int subMeshIndex; // 0x20
		public Vector3 position; // 0x24
		public Vector3 scale; // 0x30
		public Quaternion rotation; // 0x3C
		public Vector4 lightmapScaleOffset; // 0x4C
		public bool intersectsSurface; // 0x5C
		public int startNewTriangleIndex; // 0x60
		public int newTriangleCount; // 0x64
		public bool skip; // 0x68

		// Constructors
		public MeshObject(CachedGameObject cachedGO, int subMeshIndex); // 0x003A6210-0x003A63A0
	}

	[Serializable]
	public class CachedGameObject // TypeDefIndex: 3079
	{
		// Fields
		public GameObject go; // 0x10
		public Transform t; // 0x18
		public MeshRenderer mr; // 0x20
		public MeshFilter mf; // 0x28
		public Mesh mesh; // 0x30

		// Constructors
		public CachedGameObject(GameObject go, Transform t, MeshRenderer mr, MeshFilter mf, Mesh mesh); // 0x00408520-0x00408540
		public CachedGameObject(CachedComponents cachedComponent); // 0x00408540-0x004085C0
	}

	[Serializable]
	public class CachedLodGameObject : CachedGameObject // TypeDefIndex: 3080
	{
		// Fields
		public Vector3 center; // 0x38
		public int lodCount; // 0x44
		public int lodLevel; // 0x48

		// Constructors
		public CachedLodGameObject(CachedGameObject cachedGO, int lodCount, int lodLevel); // 0x004085C0-0x004085F0
	}

	[ExecuteInEditMode] // 0x00254CD0-0x00254CE0
	public class CreateOverlapColliders : MonoBehaviour // TypeDefIndex: 3081
	{
		// Fields
		public LayerMask layerMask; // 0x18
		public bool create; // 0x1C
		public bool destroy; // 0x1D
		public GameObject newGO; // 0x20
		public int lodLevel; // 0x28
		public bool setLayer; // 0x2C
		public static bool foundLodGroup; // 0x00
		public static Dictionary<GameObject, GameObject> lookupOrigCollider; // 0x08
		public static Dictionary<GameObject, GameObject> lookupColliderOrig; // 0x10
		public static Dictionary<Collider, LodInfo> lodInfoLookup; // 0x18
		private static FastList<LodInfo> lodInfos; // 0x20
		private static FastList<GameObject> selectGos; // 0x28
		private static HashSet<Mesh> lodGroupMeshes; // 0x30
		private static int overlapLayer; // 0x38
		private static FastList<Collider> colliders; // 0x40

		// Nested types
		public class LodInfo // TypeDefIndex: 3082
		{
			// Fields
			public FastList<LodLevel> lodLevels; // 0x10

			// Constructors
			public LodInfo(); // 0x003DA840-0x003DA8E0

			// Methods
			public void SetActiveOnlyLodLevel(int lodLevel); // 0x003D9CA0-0x003D9D20
			public void SetActiveOtherLodLevels(int excludeLevel); // 0x003D9DE0-0x003D9E60
			public void SetLayerLodLevel(int lodLevel, int layer, int otherLayer); // 0x003D9E60-0x003D9EE0
			public void CreateLodGroupColliders(LODGroup lodGroup, Transform parentT); // 0x003D9FA0-0x003DA730
		}

		public class LodLevel // TypeDefIndex: 3083
		{
			// Fields
			public FastList<Collider> colliders; // 0x10
			public FastList<GameObject> gos; // 0x18

			// Constructors
			public LodLevel(); // 0x003DA730-0x003DA840

			// Methods
			public void SetCollidersActive(bool active); // 0x003D9D20-0x003D9DE0
			public void SetLayer(int layer); // 0x003D9EE0-0x003D9FA0
		}

		// Constructors
		public CreateOverlapColliders(); // 0x00356E00-0x00356E40
		static CreateOverlapColliders(); // 0x00356E40-0x00357110

		// Methods
		private void Update(); // 0x00355480-0x003555C0
		public static void SaveCollidersState(LayerMask layerMask); // 0x00356200-0x00356450
		public static void RestoreCollidersState(); // 0x00356040-0x00356200
		public static void EnableLodLevelCollider(int lodLevel, int lodGroupLayer); // 0x00355F20-0x00356040
		public static bool IsAnythingOnFreeLayers(int insideLayer, int lodGroupLayer); // 0x00356950-0x00356C20
		public static void Create(Transform parentT, LayerMask overlapLayerMask, int lodGroupLayer, ref GameObject overlapCollidersGO); // 0x003555C0-0x00355E80
		private static MeshCollider CreateMeshCollider(MeshFilter mf, Transform parentT, string prefixName); // 0x00356450-0x00356950
		public static void DestroyOverlapColliders(GameObject go); // 0x00355E80-0x00355F20
		public static void CopyTransform(Transform st, Transform dt); // 0x00356C20-0x00356E00
	}

	[ExecuteInEditMode] // 0x00254CE0-0x00254CF0
	public class RandomizeTransform : MonoBehaviour // TypeDefIndex: 3084
	{
		// Fields
		public Vector2 scaleRange; // 0x18

		// Constructors
		public RandomizeTransform(); // 0x003B8790-0x003B87E0

		// Methods
		private void OnEnable(); // 0x003B84F0-0x003B8790
	}

	public static class RemoveOverlappingTris // TypeDefIndex: 3085
	{
		// Fields
		public static FastList<Triangle3> triangles; // 0x00
		private static FastList<ColliderInfo> collidersInfo; // 0x08
		private static FastList<Collider> colliders; // 0x10
		private static FastList<RaycastHit> hitInfos; // 0x18
		private static FastList<RaycastHit> hitInfos2; // 0x20
		private static RaycastHit hitInfo; // 0x28
		private static HashSet<GameObject> toCombineGos; // 0x58
		private static Triangle3 tri; // 0x60

		// Nested types
		private struct ColliderInfo // TypeDefIndex: 3086
		{
			// Fields
			public GameObject go; // 0x00
			public int layer; // 0x08
		}

		// Constructors
		static RemoveOverlappingTris(); // 0x003BDF60-0x003BE280

		// Methods
		public static void RemoveOverlap(Transform t, MeshCombineJobManager.MeshCombineJob meshCombineJob, MeshCache.SubMeshCache newMeshCache, ref byte[] vertexIsInsideCollider); // 0x003BAE90-0x003BC2B0
		private static bool CheckAnyInsideOfLodGroups(int layerMask, int lodLevel); // 0x003BCCF0-0x003BDDB0
		private static bool IsOneColliderGOInToCombineGos(); // 0x003BCAE0-0x003BCCF0
		private static bool AreAllHitInfosALodGroup(); // 0x003BC990-0x003BCAE0
		private static bool AnythingInside(); // 0x003BC2B0-0x003BC4F0
		private static bool Linecast(Vector3 p1, Vector3 p2, int layerMask); // 0x003BDDB0-0x003BDF60
		private static bool LinecastAll(Vector3 p1, Vector3 p2, int layerMask); // 0x003BC4F0-0x003BC6D0
		private static bool IntersectAny(); // 0x003BC6D0-0x003BC990
	}
}

namespace MalbersAnimations
{
	public class Readme : ScriptableObject // TypeDefIndex: 3087
	{
		// Fields
		public Texture2D icon; // 0x18
		public string title; // 0x20
		public Section[] sections; // 0x28

		// Nested types
		[Serializable]
		public class Section // TypeDefIndex: 3088
		{
			// Fields
			public string heading; // 0x10
			public string text; // 0x18
			public string linkText; // 0x20
			public string url; // 0x28

			// Constructors
			public Section(); // 0x003E5BA0-0x003E5BB0
		}

		// Constructors
		public Readme(); // 0x003B8820-0x003B8830
	}

	public class UseTransform : MonoBehaviour // TypeDefIndex: 3089
	{
		// Fields
		public Transform Reference; // 0x18
		public bool rotation; // 0x20
		public UpdateMode updateMode; // 0x24

		// Nested types
		public enum UpdateMode // TypeDefIndex: 3090
		{
			Update = 1,
			FixedUpdate = 2,
			LateUpdate = 4
		}

		// Constructors
		public UseTransform(); // 0x003D7700-0x003D7750

		// Methods
		private void Update(); // 0x003D74B0-0x003D74C0
		private void LateUpdate(); // 0x003D76E0-0x003D76F0
		private void FixedUpdate(); // 0x003D76F0-0x003D7700
		private void SetTransformReference(); // 0x003D74C0-0x003D76E0
	}
}

namespace MalbersAnimations.Events
{
	public class UnityEventRaiser : MonoBehaviour // TypeDefIndex: 3091
	{
		// Fields
		public float Delayed; // 0x18
		public UnityEvent OnEnableEvent; // 0x20

		// Constructors
		public UnityEventRaiser(); // 0x003D72C0-0x003D7300

		// Methods
		public void OnEnable(); // 0x003D7120-0x003D71D0
		private void StartEvent(); // 0x003D71D0-0x003D71F0
		public void DestroyMe(float time); // 0x003D71F0-0x003D72C0
	}
}

namespace EpicToonFX
{
	public class ETFXButtonScript : MonoBehaviour // TypeDefIndex: 3092
	{
		// Fields
		public GameObject Button; // 0x18
		private Text MyButtonText; // 0x20
		private string projectileParticleName; // 0x28
		private ETFXFireProjectile effectScript; // 0x30
		private ETFXProjectileScript projectileScript; // 0x38
		public float buttonsX; // 0x40
		public float buttonsY; // 0x44
		public float buttonsSizeX; // 0x48
		public float buttonsSizeY; // 0x4C
		public float buttonsDistance; // 0x50

		// Constructors
		public ETFXButtonScript(); // 0x0035AEF0-0x0035AF30

		// Methods
		private void Start(); // 0x0035AAA0-0x0035ABD0
		private void Update(); // 0x0035AC60-0x0035AC90
		public void getProjectileNames(); // 0x0035ABD0-0x0035AC60
		public bool overButton(); // 0x0035AC90-0x0035AEF0
	}

	public class ETFXFireProjectile : MonoBehaviour // TypeDefIndex: 3093
	{
		// Fields
		[SerializeField] // 0x002552F0-0x00255300
		public GameObject[] projectiles; // 0x18
		public Transform spawnPosition; // 0x20
		public int currentProjectile; // 0x28
		public float speed; // 0x2C
		private ETFXButtonScript selectedProjectileButton; // 0x30
		private RaycastHit hit; // 0x38

		// Constructors
		public ETFXFireProjectile(); // 0x0035B840-0x0035B890

		// Methods
		private void Start(); // 0x0035AF30-0x0035AFC0
		private void Update(); // 0x0035AFC0-0x0035B7C0
		public void nextEffect(); // 0x0035B7C0-0x0035B800
		public void previousEffect(); // 0x0035B800-0x0035B830
		public void AdjustSpeed(float newSpeed); // 0x0035B830-0x0035B840
	}

	public class ETFXLoopScript : MonoBehaviour // TypeDefIndex: 3094
	{
		// Fields
		public GameObject chosenEffect; // 0x18
		public float loopTimeLimit; // 0x20
		public bool spawnWithoutLight; // 0x24
		public bool spawnWithoutSound; // 0x25

		// Nested types
		private sealed class <EffectLoop>d__6 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 3095
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public ETFXLoopScript <>4__this; // 0x20
			private GameObject <effectPlayer>5__2; // 0x28

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x00256290-0x002562A0 */ get; } // 0x003DACB0-0x003DACC0
			object IEnumerator.Current { [DebuggerHidden] /* 0x002562A0-0x002562B0 */ get; } // 0x003DACC0-0x003DACD0

			// Constructors
			[DebuggerHidden] // 0x00256270-0x00256280
			public <EffectLoop>d__6(int <>1__state); // 0x003DA8E0-0x003DA8F0

			// Methods
			[DebuggerHidden] // 0x00256280-0x00256290
			void IDisposable.Dispose(); // 0x003DA8F0-0x003DA900
			private bool MoveNext(); // 0x003DA900-0x003DACB0
		}

		// Constructors
		public ETFXLoopScript(); // 0x0035BDD0-0x0035BE20

		// Methods
		private void Start(); // 0x0035BD00-0x0035BD40
		public void PlayEffect(); // 0x0035BD40-0x0035BD80
		private IEnumerator EffectLoop(); // 0x0035BD80-0x0035BDD0
	}

	public class ETFXMouseOrbit : MonoBehaviour // TypeDefIndex: 3096
	{
		// Fields
		public Transform target; // 0x18
		public float distance; // 0x20
		public float xSpeed; // 0x24
		public float ySpeed; // 0x28
		public float yMinLimit; // 0x2C
		public float yMaxLimit; // 0x30
		public float distanceMin; // 0x34
		public float distanceMax; // 0x38
		public float smoothTime; // 0x3C
		private float rotationYAxis; // 0x40
		private float rotationXAxis; // 0x44
		private float velocityX; // 0x48
		private float velocityY; // 0x4C

		// Constructors
		public ETFXMouseOrbit(); // 0x0035CA20-0x0035CA80

		// Methods
		private void Start(); // 0x0035BE20-0x0035BFA0
		private void LateUpdate(); // 0x0035BFA0-0x0035C950
		public static float ClampAngle(float angle, float min, float max); // 0x0035C950-0x0035CA20
	}

	public class ETFXTarget : MonoBehaviour // TypeDefIndex: 3097
	{
		// Fields
		public GameObject hitParticle; // 0x18
		public GameObject respawnParticle; // 0x20
		private Renderer targetRenderer; // 0x28
		private Collider targetCollider; // 0x30

		// Nested types
		private sealed class <Respawn>d__7 : IEnumerator<object>, IEnumerator, IDisposable // TypeDefIndex: 3098
		{
			// Fields
			private int <>1__state; // 0x10
			private object <>2__current; // 0x18
			public ETFXTarget <>4__this; // 0x20

			// Properties
			object IEnumerator<System.Object>.Current { [DebuggerHidden] /* 0x002562D0-0x002562E0 */ get; } // 0x003DAD70-0x003DAD80
			object IEnumerator.Current { [DebuggerHidden] /* 0x002562E0-0x002562F0 */ get; } // 0x003DAD80-0x003DAD90

			// Constructors
			[DebuggerHidden] // 0x002562B0-0x002562C0
			public <Respawn>d__7(int <>1__state); // 0x003DACD0-0x003DACE0

			// Methods
			[DebuggerHidden] // 0x002562C0-0x002562D0
			void IDisposable.Dispose(); // 0x003DACE0-0x003DACF0
			private bool MoveNext(); // 0x003DACF0-0x003DAD70
		}

		// Constructors
		public ETFXTarget(); // 0x0035F230-0x0035F270

		// Methods
		private void Start(); // 0x0035EBD0-0x0035EC20
		private void SpawnTarget(); // 0x0035EC20-0x0035EEB0
		private void OnTriggerEnter(Collider col); // 0x0035EEB0-0x0035F1E0
		private IEnumerator Respawn(); // 0x0035F1E0-0x0035F230
	}

	public class ETFXLightFade : MonoBehaviour // TypeDefIndex: 3099
	{
		// Fields
		public float life; // 0x18
		public bool killAfterLife; // 0x1C
		private Light li; // 0x20
		private float initIntensity; // 0x28

		// Constructors
		public ETFXLightFade(); // 0x0035BCB0-0x0035BD00

		// Methods
		private void Start(); // 0x0035B890-0x0035BA50
		private void Update(); // 0x0035BA50-0x0035BCB0
	}

	public class ETFXPitchRandomizer : MonoBehaviour // TypeDefIndex: 3100
	{
		// Fields
		public float randomPercent; // 0x18

		// Constructors
		public ETFXPitchRandomizer(); // 0x0035CC10-0x0035CC60

		// Methods
		private void Start(); // 0x0035CA80-0x0035CC10
	}

	public class ETFXRotation : MonoBehaviour // TypeDefIndex: 3101
	{
		// Fields
		public Vector3 rotateVector; // 0x18
		public spaceEnum rotateSpace; // 0x24

		// Nested types
		public enum spaceEnum // TypeDefIndex: 3102
		{
			Local = 0,
			World = 1
		}

		// Constructors
		public ETFXRotation(); // 0x0035E110-0x0035E1E0

		// Methods
		private void Update(); // 0x0035DF00-0x0035E110
	}
}

namespace Lightbug.Utilities
{
	public struct Contact // TypeDefIndex: 3103
	{
		// Fields
		public bool firstContact; // 0x00
		public Vector3 point; // 0x04
		public Vector3 normal; // 0x10
		public Collider2D collider2D; // 0x20
		public Collider collider3D; // 0x28
		public bool isRigidbody; // 0x30
		public bool isKinematicRigidbody; // 0x31
		public Vector3 pointVelocity; // 0x34
		public GameObject gameObject; // 0x40
	}

	public struct HitInfo // TypeDefIndex: 3104
	{
		// Fields
		public bool hit; // 0x00
		public Vector3 normal; // 0x04
		public Vector3 point; // 0x10
		public float distance; // 0x1C
		public Vector3 direction; // 0x20
		public Transform transform; // 0x30
		public Collider2D collider2D; // 0x38
		public Collider collider3D; // 0x40
		public Rigidbody2D rigidbody2D; // 0x48
		public Rigidbody rigidbody3D; // 0x50
	}

	public struct OrthonormalReference // TypeDefIndex: 3105
	{
		// Fields
		public Vector3 forward; // 0x00
		public Vector3 up; // 0x0C
		public Vector3 right; // 0x18

		// Methods
		public void Update(Transform transform); // 0x00256B20-0x00256B70
		public void Update(Transform transform, Vector3 planeNormal); // 0x00256B70-0x00256B80
		public void Update(Vector3 right, Vector3 up, Vector3 forward); // 0x00256B80-0x00256D40
	}

	public abstract class PhysicsComponent : MonoBehaviour // TypeDefIndex: 3106
	{
		// Fields
		protected int hits; // 0x18
		public List<Contact> contactsList; // 0x20
		protected List<GameObject> triggers; // 0x28
		private Action<Contact> OnCollisionEnterEvent; // 0x30
		private Action<GameObject> OnTriggerEnterEvent; // 0x38
		private Action<GameObject> OnTriggerExitEvent; // 0x40

		// Properties
		public List<GameObject> Triggers { get; } // 0x003B3CF0-0x003B3D00

		// Events
		public event Action<Contact> OnCollisionEnterEvent {{
			add; // 0x003B3D00-0x003B3D90
			remove; // 0x003B3D90-0x003B3E20
		}
		public event Action<GameObject> OnTriggerEnterEvent {{
			add; // 0x003B3E20-0x003B3EB0
			remove; // 0x003B3EB0-0x003B3F40
		}
		public event Action<GameObject> OnTriggerExitEvent {{
			add; // 0x003B3F40-0x003B3FD0
			remove; // 0x003B3FD0-0x003B4060
		}

		// Constructors
		protected PhysicsComponent(); // 0x003B42B0-0x003B4360

		// Methods
		protected virtual void Awake(); // 0x003B4060-0x003B40B0
		protected void OnCollisionEnterMethod(Contact contact); // 0x003B40B0-0x003B4120
		protected void OnTriggerEnterMethod(GameObject trigger); // 0x003B4120-0x003B4190
		protected void OnTriggerExitMethod(GameObject trigger); // 0x003B4190-0x003B4260
		public abstract void IgnoreLayerCollision(int layerA, int layerB, bool ignore);
		public void ClearContacts(); // 0x003B4260-0x003B42B0
		protected abstract void AddContacts(int bufferHits, bool firstContact);
		public abstract int Raycast(out HitInfo hitInfo, Vector3 origin, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB0 */);
		public abstract int SphereCast(out HitInfo hitInfo, Vector3 center, float radius, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB1 */);
		public abstract int CapsuleCast(out HitInfo hitInfo, Vector3 bottom, Vector3 top, float radius, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB2 */);
		public abstract bool OverlapSphere(Vector3 center, float radius, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB3 */);
		public abstract bool OverlapCapsule(Vector3 bottom, Vector3 top, float radius, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB4 */);
	}

	public sealed class PhysicsComponent2D : PhysicsComponent // TypeDefIndex: 3107
	{
		// Fields
		private RaycastHit2D[] raycastHits; // 0x48
		private Collider2D[] overlappedColliders; // 0x50
		private ContactPoint2D[] contactsBuffer; // 0x58

		// Constructors
		public PhysicsComponent2D(); // 0x003B5A70-0x003B5B80

		// Methods
		private void OnTriggerEnter2D(Collider2D other); // 0x003B4360-0x003B4420
		private void OnTriggerExit2D(Collider2D other); // 0x003B4420-0x003B4490
		private void OnCollisionEnter2D(Collision2D collision); // 0x003B4490-0x003B44D0
		private void OnCollisionStay2D(Collision2D collision); // 0x003B44D0-0x003B4510
		public override void IgnoreLayerCollision(int layerA, int layerB, bool ignore); // 0x003B4510-0x003B4570
		protected override void AddContacts(int bufferHits, bool firstContact); // 0x003B4570-0x003B4A80
		public override int Raycast(out HitInfo hitInfo, Vector3 origin, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB5 */); // 0x003B4A80-0x003B4C60
		public override int CapsuleCast(out HitInfo hitInfo, Vector3 bottom, Vector3 top, float radius, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB6 */); // 0x003B4FF0-0x003B54D0
		public override int SphereCast(out HitInfo hitInfo, Vector3 center, float radius, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB7 */); // 0x003B54D0-0x003B56C0
		public override bool OverlapSphere(Vector3 center, float radius, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB8 */); // 0x003B56C0-0x003B57A0
		public override bool OverlapCapsule(Vector3 bottom, Vector3 top, float radius, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEB9 */); // 0x003B57A0-0x003B5A70
		private void GetHitInfo(ref HitInfo hitInfo, RaycastHit2D raycastHit, Vector3 castDirection); // 0x003B4E60-0x003B4FF0
		private void GetClosestHit(out HitInfo hitInfo, Vector3 castDisplacement, LayerMask layerMask); // 0x003B4C60-0x003B4E60
	}

	public sealed class PhysicsComponent3D : PhysicsComponent // TypeDefIndex: 3108
	{
		// Fields
		private RaycastHit[] raycastHits; // 0x48
		private Collider[] overlappedColliders; // 0x50
		private ContactPoint[] contactsBuffer; // 0x58

		// Constructors
		public PhysicsComponent3D(); // 0x003B6B40-0x003B6C50

		// Methods
		private void OnTriggerEnter(Collider other); // 0x003B5B80-0x003B5C40
		private void OnTriggerExit(Collider other); // 0x003B5C40-0x003B5CB0
		private void OnCollisionEnter(Collision collision); // 0x003B5CB0-0x003B5CF0
		private void OnCollisionStay(Collision collision); // 0x003B5CF0-0x003B5D30
		public override void IgnoreLayerCollision(int layerA, int layerB, bool ignore); // 0x003B5D30-0x003B5D90
		protected override void AddContacts(int bufferHits, bool firstContact); // 0x003B5D90-0x003B6300
		public override int Raycast(out HitInfo hitInfo, Vector3 origin, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEBA */); // 0x003B6300-0x003B6460
		public override int CapsuleCast(out HitInfo hitInfo, Vector3 bottom, Vector3 top, float radius, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEBB */); // 0x003B6800-0x003B6990
		public override int SphereCast(out HitInfo hitInfo, Vector3 center, float radius, Vector3 castDisplacement, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEBC */); // 0x003B6990-0x003B6B00
		public override bool OverlapSphere(Vector3 center, float radius, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEBD */); // 0x003B6B00-0x003B6B20
		public override bool OverlapCapsule(Vector3 bottom, Vector3 top, float radius, LayerMask layerMask, bool ignoreTrigger = true /* Metadata: 0x0015AEBE */); // 0x003B6B20-0x003B6B40
		private void GetHitInfo(ref HitInfo hitInfo, RaycastHit raycastHit, Vector3 castDirection); // 0x003B6690-0x003B6800
		private void GetClosestHit(out HitInfo hitInfo, Vector3 castDisplacement, LayerMask layerMask); // 0x003B6460-0x003B6690
	}

	public static class PhysicsUtilities // TypeDefIndex: 3109
	{
		// Methods
		public static bool SphereCast(Vector3 center, float radius, Vector3 castDisplacement, LayerMask layerMask, out RaycastHit raycastHit, bool ignoreTrigger = true /* Metadata: 0x0015AEBF */); // 0x003B6C50-0x003B6DF0
		public static bool SphereCast(Vector3 center, float radius, Vector3 castDisplacement, LayerMask layerMask, out RaycastHit2D raycastHit, bool ignoreTrigger = true /* Metadata: 0x0015AEC0 */); // 0x003B6DF0-0x003B70A0
	}

	public abstract class RigidbodyComponent : MonoBehaviour // TypeDefIndex: 3110
	{
		// Properties
		public abstract float Mass { get; set; }
		public abstract bool IsKinematic { get; set; }
		public abstract bool UseGravity { get; set; }
		public abstract bool UseInterpolation { get; set; }
		public abstract bool ContinuousCollisionDetection { get; set; }
		public abstract RigidbodyConstraints Constraints { get; set; }
		public Vector3 Up { get; } // 0x003BE280-0x003BE490
		public Vector3 Forward { get; } // 0x003BE490-0x003BE6A0
		public Vector3 Right { get; } // 0x003BE6A0-0x003BE8B0
		public abstract Vector3 Position { get; set; }
		public abstract Quaternion Rotation { get; set; }
		public abstract Vector3 Velocity { get; set; }

		// Constructors
		protected RigidbodyComponent(); // 0x003BE900-0x003BE940

		// Methods
		public abstract void SetPositionAndRotation(Vector3 position, Quaternion rotation);
		public abstract void Interpolate(Vector3 position);
		public abstract void Interpolate(Vector3 position, Quaternion rotation);
		public abstract Vector3 GetPointVelocity(Vector3 point);
		public abstract void AddForceToRigidbody(Vector3 force, ForceMode forceMode = ForceMode.Force /* Metadata: 0x0015AEC1 */);
		protected virtual void Awake(); // 0x003BE8B0-0x003BE900
	}

	public sealed class RigidbodyComponent2D : RigidbodyComponent // TypeDefIndex: 3111
	{
		// Fields
		private Rigidbody2D rigidbody; // 0x18

		// Properties
		public override float Mass { get; set; } // 0x003BEA40-0x003BEA90 0x003BEA90-0x003BEB00
		public override bool IsKinematic { get; set; } // 0x003BEB00-0x003BEB60 0x003BEB60-0x003BEBC0
		public override bool UseGravity { get; set; } // 0x003BEBC0-0x003BEC20 0x003BEC20-0x003BECA0
		public override bool UseInterpolation { get; set; } // 0x003BECA0-0x003BED00 0x003BED00-0x003BED60
		public override bool ContinuousCollisionDetection { get; set; } // 0x003BED60-0x003BEDC0 0x003BEDC0-0x003BEE20
		public override RigidbodyConstraints Constraints { get; set; } // 0x003BEE20-0x003BEE90 0x003BEE90-0x003BF050
		public override Vector3 Position { get; set; } // 0x003BF050-0x003BF110 0x003BF110-0x003BF1C0
		public override Quaternion Rotation { get; set; } // 0x003BF1C0-0x003BF270 0x003BF270-0x003BF2F0
		public override Vector3 Velocity { get; set; } // 0x003BF2F0-0x003BF3B0 0x003BF3B0-0x003BF460

		// Constructors
		public RigidbodyComponent2D(); // 0x003BF8D0-0x003BF910

		// Methods
		protected override void Awake(); // 0x003BE940-0x003BEA40
		public override void Interpolate(Vector3 position); // 0x003BF460-0x003BF510
		public override void Interpolate(Vector3 position, Quaternion rotation); // 0x003BF510-0x003BF620
		public override void SetPositionAndRotation(Vector3 position, Quaternion rotation); // 0x003BF620-0x003BF730
		public override Vector3 GetPointVelocity(Vector3 point); // 0x003BF730-0x003BF800
		public override void AddForceToRigidbody(Vector3 force, ForceMode forceMode = ForceMode.Force /* Metadata: 0x0015AEC5 */); // 0x003BF800-0x003BF8D0
	}

	public sealed class RigidbodyComponent3D : RigidbodyComponent // TypeDefIndex: 3112
	{
		// Fields
		private Rigidbody rigidbody; // 0x18

		// Properties
		public override float Mass { get; set; } // 0x003BFA10-0x003BFA60 0x003BFA60-0x003BFAD0
		public override bool IsKinematic { get; set; } // 0x003BFAD0-0x003BFB20 0x003BFB20-0x003BFB80
		public override bool UseGravity { get; set; } // 0x003BFB80-0x003BFBD0 0x003BFBD0-0x003BFC30
		public override bool UseInterpolation { get; set; } // 0x003BFC30-0x003BFC90 0x003BFC90-0x003BFCF0
		public override bool ContinuousCollisionDetection { get; set; } // 0x003BFCF0-0x003BFD50 0x003BFD50-0x003BFDB0
		public override RigidbodyConstraints Constraints { get; set; } // 0x003BFDB0-0x003BFE00 0x003BFE00-0x003BFE60
		public override Vector3 Position { get; set; } // 0x003BFE60-0x003BFEE0 0x003BFEE0-0x003BFF50
		public override Quaternion Rotation { get; set; } // 0x003BFF50-0x003BFFC0 0x003BFFC0-0x003C0030
		public override Vector3 Velocity { get; set; } // 0x003C0030-0x003C00B0 0x003C00B0-0x003C0120

		// Constructors
		public RigidbodyComponent3D(); // 0x003C0440-0x003C0480

		// Methods
		protected override void Awake(); // 0x003BF910-0x003BFA10
		public override void Interpolate(Vector3 position); // 0x003C0120-0x003C0190
		public override void Interpolate(Vector3 position, Quaternion rotation); // 0x003C0190-0x003C0270
		public override void SetPositionAndRotation(Vector3 position, Quaternion rotation); // 0x003C0270-0x003C0340
		public override Vector3 GetPointVelocity(Vector3 point); // 0x003C0340-0x003C03D0
		public override void AddForceToRigidbody(Vector3 force, ForceMode forceMode = ForceMode.Force /* Metadata: 0x0015AEC9 */); // 0x003C03D0-0x003C0440
	}

	public static class CustomUtilities // TypeDefIndex: 3113
	{
		// Methods
		public static Vector3 ProjectVectorOnPlane(Vector3 vector, Vector3 planeNormal, Vector3 rotationAxis, bool mantainMagnitud = true /* Metadata: 0x0015AECD */); // 0x00357230-0x00357660
		public static Vector3 RemoveComponent(Vector3 vector, Vector3 component); // 0x00357660-0x00357710
		public static Vector3 DeflectVector(Vector3 vector, Vector3 groundNormal, Vector3 planeNormal, bool mantainMagnitude = false /* Metadata: 0x0015AECE */); // 0x00357710-0x00357880
		public static bool isBetween(float target, float a, float b, bool inclusive = false /* Metadata: 0x0015AECF */); // 0x00357880-0x003578E0
		public static T GetOrAddComponent<T>(GameObject targetGameObject)
			where T : Component;
		public static bool BelongsToLayerMask(int layer, int layerMask); // 0x003578E0-0x003578F0
		public static void DrawArrowGizmo(Vector3 start, Vector3 end, Color color, float radius = 0.25f /* Metadata: 0x0015AED0 */); // 0x003578F0-0x00357E60
	}
}

namespace Lightbug.CharacterControllerPro.Implementation
{
	public enum CameraPositionMode // TypeDefIndex: 3114
	{
		Bounds = 0,
		Point = 1
	}

	public class Camera2D : KinematicCamera // TypeDefIndex: 3115
	{
		// Fields
		[SerializeField] // 0x00255300-0x00255310
		private Transform target; // 0x28
		[SerializeField] // 0x00255310-0x00255320
		private Vector2 cameraAABBSize; // 0x30
		[SerializeField] // 0x00255320-0x00255330
		private Vector2 targetAABBSize; // 0x38
		[SerializeField] // 0x00255330-0x00255340
		private CameraPositionMode mode; // 0x40
		[SerializeField] // 0x00255340-0x00255350
		private Vector3 offset; // 0x44
		[SerializeField] // 0x00255350-0x00255360
		private float smoothTargetTime; // 0x50
		[SerializeField] // 0x00255360-0x00255370
		private bool followRotation; // 0x54
		[SerializeField] // 0x00255370-0x00255380
		private float slerpFactor; // 0x58
		[SerializeField] // 0x00255380-0x00255390
		private float lookAheadSpeed; // 0x5C
		[SerializeField] // 0x00255390-0x002553A0
		private float xLookAheadAmount; // 0x60
		[SerializeField] // 0x002553A0-0x002553B0
		private float yLookAheadAmount; // 0x64
		private float xCurrentLookAheadAmount; // 0x68
		private float yCurrentLookAheadAmount; // 0x6C
		private Vector3 targetCameraPosition; // 0x70
		private Vector3 smoothDampVelocity; // 0x7C
		private Bounds cameraAABB; // 0x88
		private Bounds targetBounds; // 0xA0
		private CharacterActor characterActor; // 0xB8

		// Constructors
		public Camera2D(); // 0x0040C3B0-0x0040C420

		// Methods
		protected override void Start(); // 0x0040A7D0-0x0040AC20
		private void OnDrawGizmos(); // 0x0040AC20-0x0040AF20
		public override void UpdateKinematicActor(float dt); // 0x0040AF20-0x0040B0D0
		private void UpdateTargetAABB(); // 0x0040C320-0x0040C3B0
		private void UpdateCameraAABB(float dt); // 0x0040B0D0-0x0040BF40
		private void UpdatePosition(float dt); // 0x0040C0F0-0x0040C320
		private void UpdateRotation(float dt); // 0x0040BF40-0x0040C0F0
	}

	[RequireComponent] // 0x00254CF0-0x00254D30
	public class Camera3D : KinematicCamera // TypeDefIndex: 3116
	{
		// Fields
		[SerializeField] // 0x002553B0-0x002553C0
		private CharacterActor characterActor; // 0x28
		[SerializeField] // 0x002553C0-0x002553D0
		private Vector3 offsetFromHead; // 0x30
		[SerializeField] // 0x002553D0-0x002553E0
		private bool interpolatePosition; // 0x3C
		[SerializeField] // 0x002553E0-0x002553F0
		private float positionLerpUpSpeed; // 0x40
		[SerializeField] // 0x002553F0-0x00255400
		private float positionLerpPlanarSpeed; // 0x44
		[SerializeField] // 0x00255400-0x00255410
		private bool updatePitch; // 0x48
		[SerializeField] // 0x00255410-0x00255420
		private float initialPitch; // 0x4C
		[SerializeField] // 0x00255420-0x00255430
		private float pitchSpeed; // 0x50
		[SerializeField] // 0x00255430-0x00255440
		private bool updateYaw; // 0x54
		[SerializeField] // 0x00255440-0x00255450
		private float yawSpeed; // 0x58
		[SerializeField] // 0x00255450-0x00255460
		private bool updateZoom; // 0x5C
		[SerializeField] // 0x00255460-0x00255470
		private float distanceToTarget; // 0x60
		[SerializeField] // 0x00255470-0x00255480
		private float zoomInOutSpeed; // 0x64
		[SerializeField] // 0x00255480-0x00255490
		private float zoomInOutLerpSpeed; // 0x68
		[SerializeField] // 0x00255490-0x002554A0
		private float minZoom; // 0x6C
		[SerializeField] // 0x002554A0-0x002554B0
		private float maxZoom; // 0x70
		[SerializeField] // 0x002554B0-0x002554C0
		private bool collisionDetection; // 0x74
		[SerializeField] // 0x002554C0-0x002554D0
		private float detectionRadius; // 0x78
		[SerializeField] // 0x002554D0-0x002554E0
		private LayerMask layerMask; // 0x7C
		private CharacterBrain characterBrain; // 0x80
		private float pitch; // 0x88
		private float currentDistanceToTarget; // 0x8C
		private float smoothedDistanceToTarget; // 0x90
		private OrthonormalReference orthonormalReference; // 0x94
		private float deltaYaw; // 0xB8
		private float deltaPitch; // 0xBC
		private float deltaZoom; // 0xC0
		private Vector3 previousTargetPosition; // 0xC4
		private Vector3 characterPosition; // 0xD0

		// Properties
		public OrthonormalReference OrthonormalReference { get; } // 0x0040C420-0x0040C450

		// Constructors
		public Camera3D(); // 0x0040E370-0x0040E4B0

		// Methods
		protected override void Start(); // 0x0040C450-0x0040CA90
		private void Update(); // 0x0040CAE0-0x0040CB60
		private void GetInputs(); // 0x0040CB60-0x0040CBE0
		public override void UpdateKinematicActor(float dt); // 0x0040CBE0-0x0040DBC0
		private void GetTargetPosition(ref Vector3 targetPosition, float dt); // 0x0040DBC0-0x0040E150
		private void DetectCollisions(ref Vector3 displacement, Vector3 lookAtPosition); // 0x0040E150-0x0040E370
	}

	public enum SequenceType // TypeDefIndex: 3117
	{
		Duration = 0,
		OnWallHit = 1
	}

	[Serializable]
	public class CharacterAIAction // TypeDefIndex: 3118
	{
		// Fields
		public SequenceType sequenceType; // 0x10
		public float duration; // 0x14
		public CharacterActionsInfo action; // 0x18

		// Constructors
		public CharacterAIAction(); // 0x0040F010-0x0040F020
	}

	public class CharacterAISequenceBehaviour : ScriptableObject // TypeDefIndex: 3119
	{
		// Fields
		[SerializeField] // 0x002554E0-0x002554F0
		private List<CharacterAIAction> actionSequence; // 0x18

		// Properties
		public List<CharacterAIAction> ActionSequence { get; } // 0x0040F020-0x0040F030

		// Constructors
		public CharacterAISequenceBehaviour(); // 0x0040F030-0x0040F1E0
	}

	[Serializable]
	public struct CharacterActionsInfo // TypeDefIndex: 3120
	{
		// Fields
		public AxesCompositeAction inputAxes; // 0x00
		public ButtonAction run; // 0x08
		public ButtonAction jump; // 0x0B
		public ButtonAction shrink; // 0x0E
		public ButtonAction dash; // 0x11
		public ButtonAction jetPack; // 0x14
		public ButtonAction interact; // 0x17
		public AxesCompositeAction cameraAxes; // 0x1C
		public AxisAction zoomAxis; // 0x24

		// Methods
		public void Reset(); // 0x002573D0-0x002573E0
		public void InitializeActions(); // 0x002573E0-0x00257450
	}

	[Serializable]
	public struct ButtonAction // TypeDefIndex: 3121
	{
		// Fields
		public bool isHeldDown; // 0x00
		public bool isPressed; // 0x01
		public bool isReleased; // 0x02

		// Methods
		public void Reset(); // 0x00257160-0x00257170
		public void Update(bool getState, bool getDownState, bool getUpState); // 0x00257170-0x002573D0
	}

	[Serializable]
	public struct AxisAction // TypeDefIndex: 3122
	{
		// Fields
		public float axisValue; // 0x00

		// Methods
		public void Reset(); // 0x00257090-0x002570A0
		public void Update(float getAxisState); // 0x002570A0-0x00257160
	}

	[Serializable]
	public struct AxesCompositeAction // TypeDefIndex: 3123
	{
		// Fields
		public Vector2 axesValue; // 0x00

		// Properties
		public bool AxesDetected { get; } // 0x00256EF0-0x00257090

		// Methods
		public void Reset(); // 0x00256D60-0x00256DF0
		public void Update(float getHorizontalAxisState, float getVerticalAxisState); // 0x00256DF0-0x00256EF0
	}

	public enum AIBehaviourType // TypeDefIndex: 3124
	{
		Sequence = 0,
		FollowTarget = 1
	}

	public enum HumanInputType // TypeDefIndex: 3125
	{
		UnityInputManager = 0,
		UI_Mobile = 1,
		Custom = 2
	}

	[RequireComponent] // 0x00254D30-0x00254D70
	public class CharacterBrain : MonoBehaviour // TypeDefIndex: 3126
	{
		// Fields
		[SerializeField] // 0x002554F0-0x00255500
		public bool isAI; // 0x18
		[SerializeField] // 0x00255500-0x00255510
		private InputHandler inputHandler; // 0x20
		[SerializeField] // 0x00255510-0x00255520
		private HumanInputType humanInputType; // 0x28
		public CharacterInputData inputData; // 0x30
		public AIBehaviourType behaviourType; // 0x38
		[SerializeField] // 0x00255520-0x00255530
		private bool useRawAxes; // 0x3C
		[SerializeField] // 0x00255530-0x00255540
		private CharacterAISequenceBehaviour sequenceBehaviour; // 0x40
		[SerializeField] // 0x00255540-0x00255550
		private Transform followTarget; // 0x48
		[SerializeField] // 0x00255550-0x00255560
		private float reachDistance; // 0x50
		[SerializeField] // 0x00255560-0x00255570
		private float refreshTime; // 0x54
		private CharacterActionsInfo characterActions; // 0x58
		private int currentActionIndex; // 0x80
		private float waitTime; // 0x84
		private float time; // 0x88
		private bool dirty; // 0x8C
		private CharacterActor characterActor; // 0x90
		private NavMeshPath navMeshPath; // 0x98
		[SerializeField] // 0x00255570-0x00255580
		private bool yAxisToXAxis2D; // 0xA0

		// Properties
		public bool IsAI { get; set; } // 0x00420E10-0x00420E20 0x00420E20-0x00420E30
		public CharacterActionsInfo CharacterActions { get; } // 0x00420E30-0x00420E50

		// Constructors
		public CharacterBrain(); // 0x00423200-0x00423260

		// Methods
		protected virtual void Awake(); // 0x00420E50-0x00421100
		private void OnEnable(); // 0x00421100-0x004212C0
		private void OnDisable(); // 0x004212C0-0x00421480
		private void Start(); // 0x00421480-0x00421490
		public void SetAction(CharacterActionsInfo characterAction); // 0x004219F0-0x00421A10
		public void SetSequence(CharacterAISequenceBehaviour sequenceBehaviour, bool forceUpdate = true /* Metadata: 0x0015AEF8 */); // 0x00421A10-0x00421AA0
		public void SetFollowTarget(Transform followTarget, bool forceUpdate = true /* Metadata: 0x0015AEF9 */); // 0x00421AA0-0x00421B30
		public void SetBrainType(bool AI); // 0x00421490-0x004215D0
		public void SetAIBehaviour(AIBehaviourType type); // 0x004215D0-0x004219F0
		private void Update(); // 0x00421B30-0x00421BC0
		private void OnSimulationEnd(float dt); // 0x00423180-0x00423190
		public void UpdateBrain(float dt = 0f /* Metadata: 0x0015AEFA */); // 0x00423170-0x00423180
		private void UpdateHumanBrain(float dt); // 0x00421C90-0x004224E0
		private void OnWallHit(CollisionInfo collisionInfo); // 0x00423190-0x00423200
		private void UpdateAIBrain(float dt); // 0x00421BC0-0x00421C90
		private void SelectNextSequenceElement(); // 0x004224E0-0x004227C0
		private void UpdateFollowTargetBehaviour(); // 0x004227C0-0x00423170
	}

	public class CharacterInputData : ScriptableObject // TypeDefIndex: 3127
	{
		// Fields
		public string horizontalAxis; // 0x18
		public string verticalAxis; // 0x20
		public string cameraHorizontalAxis; // 0x28
		public string cameraVerticalAxis; // 0x30
		public string cameraZoomAxis; // 0x38
		public string run; // 0x40
		public string jump; // 0x48
		public string shrink; // 0x50
		public string dash; // 0x58
		public string jetPack; // 0x60
		public string interact; // 0x68

		// Constructors
		public CharacterInputData(); // 0x00425820-0x004258D0
	}

	[RequireComponent] // 0x00254D70-0x00254DB0
	public abstract class CharacterState : MonoBehaviour // TypeDefIndex: 3128
	{
		// Fields
		private CharacterActor characterActor; // 0x18
		private CharacterBrain characterBrain; // 0x20
		private CharacterStateController characterStateController; // 0x28

		// Properties
		public CharacterActor CharacterActor { get; } // 0x004267B0-0x004268B0
		public CharacterBrain CharacterBrain { get; } // 0x004268B0-0x004269B0
		public CharacterActionsInfo CharacterActions { get; } // 0x004269B0-0x00426AE0
		public CharacterStateController CharacterStateController { get; } // 0x00426AE0-0x00426BE0
		public abstract string Name { get; }

		// Constructors
		protected CharacterState(); // 0x00426CC0-0x00426D00

		// Methods
		protected virtual void Awake(); // 0x00426BE0-0x00426C30
		public virtual void EnterBehaviour(float dt); // 0x00426C30-0x00426C40
		public virtual void PreUpdateBehaviour(float dt); // 0x00426C40-0x00426C50
		public abstract void UpdateBehaviour(float dt);
		public virtual void PostUpdateBehaviour(float dt); // 0x00426C50-0x00426C60
		public virtual void ExitBehaviour(float dt); // 0x00426C60-0x00426C70
		public virtual CharacterState CheckExitTransition(); // 0x00426C70-0x00426C80
		public virtual bool CheckEnterTransition(CharacterState fromState); // 0x00426C80-0x00426C90
		public virtual string GetInfo(); // 0x00426C90-0x00426CC0
	}

	[RequireComponent] // 0x00254DB0-0x00254E10
	public sealed class CharacterStateController : CharacterActorBehaviour // TypeDefIndex: 3129
	{
		// Fields
		private const float MaxControlValue = 100f; // Metadata: 0x0015AEFE
		private const string UntaggedTag = "Untagged"; // Metadata: 0x0015AF02
		[SerializeField] // 0x00255580-0x00255590
		private CharacterState currentState; // 0x20
		[SerializeField] // 0x00255590-0x002555A0
		private EnvironmentParameters environmentParameters; // 0x28
		[SerializeField] // 0x002555A0-0x002555B0
		private MovementReferenceParameters movementReferenceParameters; // 0x30
		private CharacterBrain characterBrain; // 0x38
		private Dictionary<string, CharacterState> states; // 0x40
		private CharacterState previousState; // 0x48
		private Action<CharacterState, CharacterState> OnStateChange; // 0x50
		private Action<Volume> OnVolumeEnter; // 0x58
		private Action<Volume> OnVolumeExit; // 0x60
		private Action<Surface> OnSurfaceEnter; // 0x68
		private Action<Surface> OnSurfaceExit; // 0x70
		private OrthonormalReference movementReference; // 0x78
		private Vector3 inputMovementReference; // 0x9C
		private Volume currentVolume; // 0xA8
		private Surface currentSurface; // 0xB0

		// Properties
		public EnvironmentParameters EnvironmentParameters { get; } // 0x00426D00-0x00426D10
		public CharacterBrain CharacterBrain { get; } // 0x00426D10-0x00426D20
		public CharacterState CurrentState { get; } // 0x004272C0-0x004272D0
		public CharacterState PreviousState { get; } // 0x004272D0-0x004272E0
		public OrthonormalReference MovementOrthonormalReference { get; } // 0x004287F0-0x00428810
		public Vector3 InputMovementReference { get; } // 0x00428810-0x00428830
		public Surface CurrentSurface { get; } // 0x00428830-0x00428840
		public float CurrentSurfaceSpeedMultiplier { get; } // 0x00428840-0x00428860
		public float CurrentSurfaceControl { get; } // 0x00428860-0x00428890
		public float RemainingSurfaceControl { get; } // 0x00428890-0x004288C0
		public Volume CurrentVolume { get; } // 0x004288C0-0x004288D0
		public float CurrentVolumeSpeedMultiplier { get; } // 0x004288D0-0x004288F0
		public float CurrentVolumeControl { get; } // 0x004288F0-0x00428920
		public float RemainingVolumeControl { get; } // 0x00428920-0x00428950
		public float CurrentGravityPositiveMultiplier { get; } // 0x00428950-0x00428970
		public float CurrentGravityNegativeMultiplier { get; } // 0x00428970-0x00428990

		// Events
		public event Action<CharacterState, CharacterState> OnStateChange {{
			add; // 0x00426D20-0x00426DB0
			remove; // 0x00426DB0-0x00426E40
		}
		public event Action<Volume> OnVolumeEnter {{
			add; // 0x00426E40-0x00426ED0
			remove; // 0x00426ED0-0x00426F60
		}
		public event Action<Volume> OnVolumeExit {{
			add; // 0x00426F60-0x00426FF0
			remove; // 0x00426FF0-0x00427080
		}
		public event Action<Surface> OnSurfaceEnter {{
			add; // 0x00427080-0x00427110
			remove; // 0x00427110-0x004271A0
		}
		public event Action<Surface> OnSurfaceExit {{
			add; // 0x004271A0-0x00427230
			remove; // 0x00427230-0x004272C0
		}

		// Constructors
		public CharacterStateController(); // 0x00428990-0x00428A60

		// Methods
		public CharacterState GetState(string stateName); // 0x004272E0-0x00427370
		public override void Initialize(CharacterActor characterActor); // 0x00427370-0x004274B0
		private void GetStates(); // 0x004274B0-0x004275D0
		public override void UpdateBehaviour(float dt); // 0x004276B0-0x00427810
		private bool CheckForTransitions(); // 0x004286A0-0x004287F0
		private void UpdateMovementReference(); // 0x00428000-0x00428380
		private void GetInputMovementReference(); // 0x00428380-0x004286A0
		private void GetSurfaceData(); // 0x00427810-0x00427AF0
		private void SetCurrentSurface(Surface surface); // 0x004275D0-0x00427640
		private void GetVolumeData(); // 0x00427AF0-0x00428000
		private void SetCurrentVolume(Volume volume); // 0x00427640-0x004276B0
	}

	[Serializable]
	public class EnvironmentParameters // TypeDefIndex: 3130
	{
		// Fields
		public MaterialsProperties materials; // 0x10

		// Constructors
		public EnvironmentParameters(); // 0x0035F3A0-0x0035F3B0
	}

	[Serializable]
	public class MovementReferenceParameters // TypeDefIndex: 3131
	{
		// Fields
		public MovementReferenceMode movementReferenceMode; // 0x10
		public Transform externalForwardReference; // 0x18

		// Nested types
		public enum MovementReferenceMode // TypeDefIndex: 3132
		{
			World = 0,
			External = 1,
			Character = 2
		}

		// Constructors
		public MovementReferenceParameters(); // 0x003A7500-0x003A7510
	}

	public class CharacterAnimation : MonoBehaviour // TypeDefIndex: 3133
	{
		// Fields
		[SerializeField] // 0x002555B0-0x002555C0
		private AnimatorPlayMode animatorPlayMode; // 0x18
		[SerializeField] // 0x002555C0-0x002555D0
		private ServerManager serverManager; // 0x20
		[SerializeField] // 0x002555D0-0x002555E0
		private string groundedName; // 0x28
		[SerializeField] // 0x002555E0-0x002555F0
		private string notGroundedName; // 0x30
		[SerializeField] // 0x002555F0-0x00255600
		private string slideName; // 0x38
		[SerializeField] // 0x00255600-0x00255610
		private string dashName; // 0x40
		[SerializeField] // 0x00255610-0x00255620
		private string jetPackName; // 0x48
		[SerializeField] // 0x00255620-0x00255630
		private string notGroundedBlendName; // 0x50
		[SerializeField] // 0x00255630-0x00255640
		private string groundBlendName; // 0x58
		[SerializeField] // 0x00255640-0x00255650
		private float notGroundedBlendSensitivity; // 0x60
		[SerializeField] // 0x00255650-0x00255660
		private float groundBlendLerpFactor; // 0x64
		[SerializeField] // 0x00255660-0x00255670
		private bool ikFootPlacement; // 0x68
		[SerializeField] // 0x00255670-0x00255680
		private float footRadius; // 0x6C
		[SerializeField] // 0x00255680-0x00255690
		private float ikExtraCastDistance; // 0x70
		[SerializeField] // 0x00255690-0x002556A0
		private string ikLeftFootWeightCurveName; // 0x78
		[SerializeField] // 0x002556A0-0x002556B0
		private string ikRightFootWeightCurveName; // 0x80
		private int slideHash; // 0x88
		private int groundedHash; // 0x8C
		private int notGroundedHash; // 0x90
		private int dashHash; // 0x94
		private int jetPackHash; // 0x98
		private float speedBlendValue; // 0x9C
		private float verticalVelocityBlendValue; // 0xA0
		private int currentStateHash; // 0xA4
		private CharacterStateController characterStateController; // 0xA8
		private CharacterActor CharacterActor; // 0xB0
		private CharacterBrain characterBrain; // 0xB8
		private Animator animator; // 0xC0

		// Nested types
		public enum AnimatorPlayMode // TypeDefIndex: 3134
		{
			Trigger = 0,
			PlayState = 1
		}

		// Constructors
		public CharacterAnimation(); // 0x00420C70-0x00420D50

		// Methods
		protected virtual void Awake(); // 0x0041F210-0x0041F9C0
		private void FixedUpdate(); // 0x0041F9C0-0x004200A0
		protected virtual bool isCurrentlyOnState(string stateName); // 0x004200A0-0x00420180
		protected virtual void PlayAnimation(int stateHash); // 0x00420180-0x004202D0
		protected virtual void UpdateBlendTreeValues(string notGroundedBlendName, string groundBlendName, float notGroundedBlendValue, float groundBlendValue); // 0x004202D0-0x004203D0
		private void OnAnimatorIK(int layerIndex); // 0x004203D0-0x004204F0
		private void AlignFoot(AvatarIKGoal footAvatar, string ikVariableName = null); // 0x004204F0-0x00420C70
	}

	public class CharacterParticles : MonoBehaviour // TypeDefIndex: 3135
	{
		// Fields
		[SerializeField] // 0x002556B0-0x002556C0
		private GameObject groundParticlesPrefab; // 0x18
		[SerializeField] // 0x002556C0-0x002556D0
		private AnimationCurve groundParticlesSpeed; // 0x20
		[SerializeField] // 0x002556D0-0x002556E0
		private AnimationCurve footstepParticleSpeed; // 0x28
		[SerializeField] // 0x002556E0-0x002556F0
		private AnimationCurve footstepParticleSize; // 0x30
		private ParticleSystem[] groundParticlesArray; // 0x38
		private ParticleSystemPooler particlesPooler; // 0x40
		private CharacterStateController characterStateController; // 0x48
		private CharacterActor CharacterActor; // 0x50

		// Constructors
		public CharacterParticles(); // 0x004266C0-0x004267A0

		// Methods
		private void Awake(); // 0x004258D0-0x00425DC0
		private void OnEnable(); // 0x00425DC0-0x00425EB0
		private void OnDisable(); // 0x00425EB0-0x00425FA0
		private void OnGroundedStateEnter(Vector3 localVelocity); // 0x00425FA0-0x004261B0
		public void PlayFootstep(); // 0x004261B0-0x004266A0
		private void Update(); // 0x004266A0-0x004266C0
	}

	public class ParticleSystemPooler // TypeDefIndex: 3136
	{
		// Fields
		private List<ParticleSystem> activeList; // 0x10
		private List<ParticleSystem> inactiveList; // 0x18

		// Constructors
		public ParticleSystemPooler(GameObject particlePrefab, Vector3 position, Quaternion rotation, int bufferLength); // 0x003B2160-0x003B23E0

		// Methods
		private ParticleSystem SelectParticle(); // 0x003B23E0-0x003B2470
		public void Instantiate(Vector3 position, Quaternion rotation, Color color, float startSpeed); // 0x003B2470-0x003B27A0
		public void Instantiate(Vector3 position, Quaternion rotation, Color color, float startSpeed, float startSize); // 0x003B27A0-0x003B2B30
		public void Update(); // 0x003B2B30-0x003B2C50
	}

	public class Dash : CharacterState // TypeDefIndex: 3137
	{
		// Fields
		private Action<Vector3> OnDashStart; // 0x30
		private Action<Vector3> OnDashEnd; // 0x38
		[SerializeField] // 0x002556F0-0x00255700
		private float initialVelocity; // 0x40
		[SerializeField] // 0x00255700-0x00255710
		private float duration; // 0x44
		[SerializeField] // 0x00255710-0x00255720
		private AnimationCurve movementCurve; // 0x48
		[SerializeField] // 0x00255720-0x00255730
		private int availableNotGroundedDashes; // 0x50
		[SerializeField] // 0x00255730-0x00255740
		private bool ignoreSpeedMultipliers; // 0x54
		[SerializeField] // 0x00255740-0x00255750
		private bool forceNotGrounded; // 0x55
		private int airDashesLeft; // 0x58
		private float dashCursor; // 0x5C
		private Vector3 dashDirection; // 0x60
		private bool isDone; // 0x6C
		private float currentSpeedMultiplier; // 0x70

		// Properties
		public override string Name { get; } // 0x003580A0-0x003580D0

		// Events
		public event Action<Vector3> OnDashStart {{
			add; // 0x00357E60-0x00357EF0
			remove; // 0x00357EF0-0x00357F80
		}
		public event Action<Vector3> OnDashEnd {{
			add; // 0x00357F80-0x00358010
			remove; // 0x00358010-0x003580A0
		}

		// Constructors
		public Dash(); // 0x003587F0-0x00358900

		// Methods
		private void OnEnable(); // 0x003580D0-0x003581D0
		private void OnDisable(); // 0x003581D0-0x003582D0
		public override string GetInfo(); // 0x003582D0-0x00358300
		private void OnGroundedStateEnter(Vector3 localVelocity); // 0x00358300-0x00358310
		public override bool CheckEnterTransition(CharacterState fromState); // 0x00358310-0x00358340
		public override CharacterState CheckExitTransition(); // 0x00358340-0x003583D0
		public override void EnterBehaviour(float dt); // 0x003583D0-0x003585D0
		public override void UpdateBehaviour(float dt); // 0x003586A0-0x003587F0
		private void ResetDash(); // 0x003585D0-0x003586A0
	}

	public class JetPack : CharacterState // TypeDefIndex: 3138
	{
		// Fields
		[SerializeField] // 0x00255750-0x00255760
		private float targetSpeed; // 0x30
		[SerializeField] // 0x00255760-0x00255770
		private float duration; // 0x34
		private Vector3 smoothDampVelocity; // 0x38
		private Vector3 jetPackVelocity; // 0x44
		private Vector3 planarVelocity; // 0x50

		// Properties
		public override string Name { get; } // 0x00367AB0-0x00367AE0

		// Constructors
		public JetPack(); // 0x003682C0-0x00368310

		// Methods
		public override string GetInfo(); // 0x00367AE0-0x00367B10
		public override void EnterBehaviour(float dt); // 0x00367B10-0x00367E40
		public override void UpdateBehaviour(float dt); // 0x00367E40-0x00367FA0
		public override CharacterState CheckExitTransition(); // 0x00368240-0x003682C0
		private void StableMovement(float dt); // 0x00367FA0-0x00368240
	}

	public class NormalMovement : CharacterState // TypeDefIndex: 3139
	{
		// Fields
		[SerializeField] // 0x00255770-0x00255780
		private PlanarMovementParameters planarMovementParameters; // 0x30
		[SerializeField] // 0x00255780-0x00255790
		private VerticalMovementParameters verticalMovementParameters; // 0x38
		[SerializeField] // 0x00255790-0x002557A0
		private ShrinkParameters shrinkParameters; // 0x40
		[SerializeField] // 0x002557A0-0x002557B0
		private RigidbodyResponseParameters rigidbodyResponseParameters; // 0x48
		private Action OnJumpPerformed; // 0x50
		private Action OnGroundedJumpPerformed; // 0x58
		private Action<int> OnNotGroundedJumpPerformed; // 0x60
		private Vector3 planarVelocity; // 0x68
		private Vector3 verticalVelocity; // 0x74
		private Vector3 externalVelocity; // 0x80
		private int notGroundedJumpsLeft; // 0x8C
		private float jumpTimer; // 0x90
		private bool isJumping; // 0x94
		private Vector3 jumpVelocity; // 0x98
		private float targetHeight; // 0xA4
		private bool wantToShrink; // 0xA8

		// Properties
		public override string Name { get; } // 0x003AA7A0-0x003AA7D0
		public bool UseGravity { get; set; } // 0x003AAF40-0x003AAF60 0x003AAF60-0x003AAF80

		// Events
		public event Action OnJumpPerformed {{
			add; // 0x003AA230-0x003AA2C0
			remove; // 0x003AA2C0-0x003AA350
		}
		public event Action OnGroundedJumpPerformed {{
			add; // 0x003AA350-0x003AA3E0
			remove; // 0x003AA3E0-0x003AA470
		}
		public event Action<int> OnNotGroundedJumpPerformed {{
			add; // 0x003AA470-0x003AA500
			remove; // 0x003AA500-0x003AA590
		}

		// Constructors
		public NormalMovement(); // 0x003AE520-0x003AE630

		// Methods
		public void ResetVelocities(); // 0x003AA590-0x003AA7A0
		protected override void Awake(); // 0x003AA7D0-0x003AA830
		private void Start(); // 0x003AA830-0x003AA920
		private void OnEnable(); // 0x003AA920-0x003AAB70
		private void OnDisable(); // 0x003AAB70-0x003AADC0
		public override string GetInfo(); // 0x003AADC0-0x003AADF0
		private void OnHeadHit(CollisionInfo collisionInfo); // 0x003AADF0-0x003AAE90
		private void OnTeleport(Vector3 position, Quaternion rotation); // 0x003AAE90-0x003AAEA0
		private void OnEnterVolume(Volume volume); // 0x003AAEA0-0x003AAF40
		public override CharacterState CheckExitTransition(); // 0x003AAF80-0x003AB1B0
		private void HandleForwardDirection(); // 0x003AB1B0-0x003AB270
		private void ProcessPlanarMovement(float dt); // 0x003AB270-0x003AC200
		private void ProcessGravity(float dt); // 0x003AC200-0x003ACB90
		private void ProcessJump(float dt); // 0x003ACB90-0x003ACDA0
		private void SetJumpVelocity(); // 0x003ACDA0-0x003AD280
		private void ProcessVerticalMovement(float dt); // 0x003AD280-0x003AD2E0
		private void VerticalDrag(float dt); // 0x003AD2E0-0x003AD8B0
		private void ProcessExternalMovement(float dt); // 0x003AD8B0-0x003ADAF0
		private void ExternalDrag(float dt); // 0x003ADAF0-0x003ADEB0
		public override void EnterBehaviour(float dt); // 0x003ADEB0-0x003AE270
		public override void UpdateBehaviour(float dt); // 0x003AE270-0x003AE2A0
		private void HandleSize(float dt); // 0x003AE2A0-0x003AE3E0
		private void HandleMovement(float dt); // 0x003AE3E0-0x003AE520
	}

	[Serializable]
	public class PlanarMovementParameters // TypeDefIndex: 3140
	{
		// Fields
		public float speed; // 0x10
		public float boostMultiplier; // 0x14
		public float notGroundedControl; // 0x18

		// Constructors
		public PlanarMovementParameters(); // 0x003AE630-0x003AE650
	}

	[Serializable]
	public class VerticalMovementParameters // TypeDefIndex: 3141
	{
		// Fields
		public bool useGravity; // 0x10
		public float jumpApexHeight; // 0x14
		public float jumpApexDuration; // 0x18
		public int availableNotGroundedJumps; // 0x1C
		public UnstableJumpMode unstableJumpMode; // 0x20
		public float jumpIntertiaMultiplier; // 0x24
		public JumpReleaseAction jumpReleaseAction; // 0x28
		public float constantJumpDuration; // 0x2C
		private float gravityMagnitude; // 0x30
		private float jumpSpeed; // 0x34

		// Properties
		public float GravityMagnitude { get; } // 0x003D7750-0x003D7760
		public float JumpSpeed { get; } // 0x003D7810-0x003D7820

		// Nested types
		public enum UnstableJumpMode // TypeDefIndex: 3142
		{
			Vertical = 0,
			GroundNormal = 1
		}

		public enum JumpReleaseAction // TypeDefIndex: 3143
		{
			Disabled = 0,
			StopJumping = 1
		}

		// Constructors
		public VerticalMovementParameters(); // 0x003D7820-0x003D7860

		// Methods
		public void UpdateParameters(float positiveGravityMultiplier); // 0x003D7760-0x003D7810
	}

	[Serializable]
	public class ShrinkParameters // TypeDefIndex: 3144
	{
		// Fields
		public float shrinkHeightRatio; // 0x10
		public ShrinkMode shrinkMode; // 0x14

		// Nested types
		public enum ShrinkMode // TypeDefIndex: 3145
		{
			Toggle = 0,
			Hold = 1
		}

		// Constructors
		public ShrinkParameters(); // 0x003AE650-0x003AE660
	}

	[Serializable]
	public class RigidbodyResponseParameters // TypeDefIndex: 3146
	{
		// Fields
		public bool reactToRigidbodies; // 0x10
		public float responseMultiplier; // 0x14
		public float maxContactVelocity; // 0x18

		// Constructors
		public RigidbodyResponseParameters(); // 0x003AE660-0x003AE680
	}

	public sealed class ActionController : MonoBehaviour // TypeDefIndex: 3147
	{
		// Fields
		[SerializeField] // 0x002557B0-0x002557C0
		private HumanInputType humanInputType; // 0x18
		[SerializeField] // 0x002557C0-0x002557D0
		private InputHandler inputHandler; // 0x20
		[SerializeField] // 0x002557D0-0x002557E0
		private bool useRawAxis; // 0x28
		[SerializeField] // 0x002557E0-0x002557F0
		private AxisData[] axis; // 0x30
		[SerializeField] // 0x002557F0-0x00255800
		private AxesData[] axes; // 0x38
		[SerializeField] // 0x00255800-0x00255810
		private ButtonData[] buttons; // 0x40
		private Dictionary<AxisData, AxisAction> axisDictionary; // 0x48
		private Dictionary<AxesData, AxesCompositeAction> axesDictionary; // 0x50
		private Dictionary<ButtonData, ButtonAction> buttonsDictionary; // 0x58

		// Constructors
		public ActionController(); // 0x004067E0-0x00406900

		// Methods
		private void Awake(); // 0x00405EA0-0x00406220
		private void Update(); // 0x00406220-0x00406230
		private void FixedUpdate(); // 0x004066B0-0x004067E0
		private void UpdateActions(); // 0x00406230-0x004066B0
	}

	[Serializable]
	public struct ButtonData // TypeDefIndex: 3148
	{
		// Fields
		public string name; // 0x00
	}

	[Serializable]
	public struct AxisData // TypeDefIndex: 3149
	{
		// Fields
		public string name; // 0x00
	}

	[Serializable]
	public struct AxesData // TypeDefIndex: 3150
	{
		// Fields
		public string horizontalName; // 0x00
		public string verticalName; // 0x08
	}

	public abstract class InputHandler : MonoBehaviour // TypeDefIndex: 3151
	{
		// Constructors
		protected InputHandler(); // 0x00367A60-0x00367AB0

		// Methods
		public abstract float GetAxis(string axisName, bool raw = true /* Metadata: 0x0015AF3A */);
		public abstract bool GetButton(string actionInputName);
		public abstract bool GetButtonDown(string actionInputName);
		public abstract bool GetButtonUp(string actionInputName);
	}

	public class UIInputHandler : InputHandler // TypeDefIndex: 3152
	{
		// Fields
		private Dictionary<string, MobileInput> axesDictionary; // 0x18

		// Constructors
		public UIInputHandler(); // 0x003D5760-0x003D5810

		// Methods
		private void Awake(); // 0x003D5420-0x003D54E0
		public override float GetAxis(string axisName, bool raw = true /* Metadata: 0x0015AF3B */); // 0x003D54E0-0x003D5580
		public override bool GetButton(string actionInputName); // 0x003D5580-0x003D5620
		public override bool GetButtonDown(string actionInputName); // 0x003D5620-0x003D56C0
		public override bool GetButtonUp(string actionInputName); // 0x003D56C0-0x003D5760
	}

	public class UnityInputHandler : InputHandler // TypeDefIndex: 3153
	{
		// Constructors
		public UnityInputHandler(); // 0x003D7470-0x003D74B0

		// Methods
		public override float GetAxis(string axisName, bool raw = true /* Metadata: 0x0015AF3C */); // 0x003D7300-0x003D7380
		public override bool GetButton(string actionInputName); // 0x003D7380-0x003D73D0
		public override bool GetButtonDown(string actionInputName); // 0x003D73D0-0x003D7420
		public override bool GetButtonUp(string actionInputName); // 0x003D7420-0x003D7470
	}

	public class MaterialsProperties : ScriptableObject // TypeDefIndex: 3154
	{
		// Fields
		[SerializeField] // 0x00255810-0x00255820
		private Surface defaultSurface; // 0x18
		[SerializeField] // 0x00255820-0x00255830
		private Volume defaultVolume; // 0x20
		[SerializeField] // 0x00255830-0x00255840
		private Surface[] surfaces; // 0x28
		[SerializeField] // 0x00255840-0x00255850
		private Volume[] volumes; // 0x30

		// Properties
		public Surface DefaultSurface { get; } // 0x00372A60-0x00372A70
		public Volume DefaultVolume { get; } // 0x00372A70-0x00372A80
		public Surface[] Surfaces { get; } // 0x00372A80-0x00372A90
		public Volume[] Volumes { get; } // 0x00372A90-0x00372AA0

		// Constructors
		public MaterialsProperties(); // 0x00372BC0-0x00372C90

		// Methods
		public bool GetSurface(string tag, ref Surface outputSurface); // 0x00372AA0-0x00372B30
		public bool GetVolume(string tag, ref Volume outputVolume); // 0x00372B30-0x00372BC0
	}

	[Serializable]
	public class Surface // TypeDefIndex: 3155
	{
		// Fields
		public string tagName; // 0x10
		public float controlMultiplier; // 0x18
		public float speedMultiplier; // 0x1C
		public Color color; // 0x20

		// Constructors
		public Surface(); // 0x003D4300-0x003D4350
	}

	[Serializable]
	public class Volume // TypeDefIndex: 3156
	{
		// Fields
		public string tagName; // 0x10
		public float controlMultiplier; // 0x18
		public float gravityPositiveMultiplier; // 0x1C
		public float gravityNegativeMultiplier; // 0x20
		public float speedMultiplier; // 0x24

		// Constructors
		public Volume(); // 0x003D7860-0x003D78A0
	}

	public class InputAxes : MonoBehaviour, IDragHandler, IEventSystemHandler, IEndDragHandler // TypeDefIndex: 3157
	{
		// Fields
		[SerializeField] // 0x00255850-0x00255860
		private MobileInput horizontalAxisMobileInput; // 0x18
		[SerializeField] // 0x00255860-0x00255870
		private MobileInput verticalAxisMobileInput; // 0x20
		[SerializeField] // 0x00255870-0x00255880
		private bool invertHorizontal; // 0x28
		[SerializeField] // 0x00255880-0x00255890
		private bool invertVertical; // 0x29
		[SerializeField] // 0x00255890-0x002558A0
		private DeadZoneMode deadZoneMode; // 0x2C
		[SerializeField] // 0x002558A0-0x002558B0
		private float deadZoneDistance; // 0x30
		[SerializeField] // 0x002558B0-0x002558C0
		private int boundsRadius; // 0x34
		[SerializeField] // 0x002558C0-0x002558D0
		private float returnLerpSpeed; // 0x38
		private Vector2 virtualPosition; // 0x3C
		private Vector2 visiblePosition; // 0x44
		private RectTransform rectTransform; // 0x50
		private Vector2 origin; // 0x58
		private bool drag; // 0x60

		// Nested types
		public enum DeadZoneMode // TypeDefIndex: 3158
		{
			Radial = 0,
			PerAxis = 1
		}

		// Constructors
		public InputAxes(); // 0x00367880-0x00367960

		// Methods
		private void Awake(); // 0x00366FA0-0x00366FE0
		private void Update(); // 0x00366FE0-0x003677E0
		public void OnDrag(PointerEventData eventData); // 0x003677E0-0x00367870
		public void OnEndDrag(PointerEventData eventData); // 0x00367870-0x00367880
	}

	public class InputButton : MonoBehaviour, IPointerUpHandler, IEventSystemHandler, IPointerDownHandler // TypeDefIndex: 3159
	{
		// Fields
		[SerializeField] // 0x002558D0-0x002558E0
		private MobileInput buttonMobileInput; // 0x18
		private bool wasHeldDown; // 0x20
		private bool <IsPressed>k__BackingField; // 0x21
		private bool <IsReleased>k__BackingField; // 0x22
		private bool <IsHeldDown>k__BackingField; // 0x23

		// Properties
		public bool IsPressed { get; set; } // 0x00367960-0x00367970 0x00367970-0x00367980
		public bool IsReleased { get; set; } // 0x00367980-0x00367990 0x00367990-0x003679A0
		public bool IsHeldDown { get; set; } // 0x003679A0-0x003679B0 0x003679B0-0x003679C0

		// Constructors
		public InputButton(); // 0x00367A20-0x00367A60

		// Methods
		public void OnPointerDown(PointerEventData eventData); // 0x003679C0-0x003679D0
		public void OnPointerUp(PointerEventData eventData); // 0x003679D0-0x003679E0
		private void Update(); // 0x003679E0-0x00367A20
	}

	public class MobileInput : MonoBehaviour // TypeDefIndex: 3160
	{
		// Fields
		[SerializeField] // 0x002558E0-0x002558F0
		private string axisName; // 0x18
		private float <AxisValue>k__BackingField; // 0x20
		private bool <IsPressed>k__BackingField; // 0x24
		private bool <IsReleased>k__BackingField; // 0x25
		private bool <IsHeldDown>k__BackingField; // 0x26

		// Properties
		public string AxisName { get; } // 0x003A70F0-0x003A7100
		public float AxisValue { get; set; } // 0x003A7100-0x003A7110 0x003A7110-0x003A7120
		public bool IsPressed { get; set; } // 0x003A7120-0x003A7130 0x003A7130-0x003A7140
		public bool IsReleased { get; set; } // 0x003A7140-0x003A7150 0x003A7150-0x003A7160
		public bool IsHeldDown { get; set; } // 0x003A7160-0x003A7170 0x003A7170-0x003A7180

		// Constructors
		public MobileInput(); // 0x003A7180-0x003A71C0
	}

	public class ActionBasedPlatform : KinematicPlatform // TypeDefIndex: 3161
	{
		// Fields
		[SerializeField] // 0x002558F0-0x00255900
		protected MovementAction movementAction; // 0x20
		[SerializeField] // 0x00255900-0x00255910
		protected RotationAction rotationAction; // 0x28

		// Constructors
		public ActionBasedPlatform(); // 0x00405E00-0x00405EA0

		// Methods
		public override void UpdateKinematicActor(float dt); // 0x00405D10-0x00405E00
	}

	[Serializable]
	public class MovementAction // TypeDefIndex: 3162
	{
		// Fields
		[SerializeField] // 0x00255910-0x00255920
		private bool enabled; // 0x10
		[SerializeField] // 0x00255920-0x00255930
		private bool infiniteDuration; // 0x11
		[SerializeField] // 0x00255930-0x00255940
		private float cycleDuration; // 0x14
		[SerializeField] // 0x00255940-0x00255950
		private bool waitAtTheEnd; // 0x18
		[SerializeField] // 0x00255950-0x00255960
		private float waitDuration; // 0x1C
		[SerializeField] // 0x00255960-0x00255970
		private Vector3 direction; // 0x20
		[SerializeField] // 0x00255970-0x00255980
		private float speed; // 0x2C
		private Vector3 actionVector; // 0x30
		private float time; // 0x3C
		private bool isWaiting; // 0x40

		// Constructors
		public MovementAction(); // 0x003A73F0-0x003A7500

		// Methods
		public void Tick(float dt, ref Vector3 position); // 0x003A71C0-0x003A73F0
	}

	public class NodeBasedPlatform : KinematicPlatform // TypeDefIndex: 3163
	{
		// Fields
		[SerializeField] // 0x00255980-0x00255990
		private bool drawHandles; // 0x20
		public bool move; // 0x21
		public bool rotate; // 0x22
		[SerializeField] // 0x00255990-0x002559A0
		private List<PlatformNode> actionsList; // 0x28
		public SequenceType sequenceType; // 0x30
		public bool positiveSequenceDirection; // 0x34
		[SerializeField] // 0x002559A0-0x002559B0
		private float globalSpeedModifier; // 0x38
		private Rigidbody2D rigidbody2D; // 0x40
		private Rigidbody rigidbody3D; // 0x48
		private ActionState actionState; // 0x50
		private Vector3 targetPosition; // 0x54
		private Vector3 targetRotation; // 0x60
		private Vector3 startingPosition; // 0x6C
		private Vector3 startingRotation; // 0x78
		private bool updateInitialPosition; // 0x84
		private Vector3 initialPosition; // 0x88
		private float time; // 0x94
		private PlatformNode currentAction; // 0x98
		private int currentActionIndex; // 0xA0

		// Properties
		public bool DrawHandles { get; } // 0x003A9250-0x003A9260
		public List<PlatformNode> ActionsList { get; } // 0x003A9260-0x003A9270
		public bool UpdateInitialPosition { get; } // 0x003A9270-0x003A9280
		public Vector3 InitialPosition { get; } // 0x003A9280-0x003A92A0
		public int CurrentActionIndex { get; } // 0x003A92A0-0x003A92B0

		// Nested types
		public enum SequenceType // TypeDefIndex: 3164
		{
			Rewind = 0,
			Loop = 1,
			OneWay = 2
		}

		private enum ActionState // TypeDefIndex: 3165
		{
			Idle = 0,
			Ready = 1,
			Waiting = 2,
			Working = 3,
			Done = 4
		}

		// Constructors
		public NodeBasedPlatform(); // 0x003AA180-0x003AA230

		// Methods
		protected override void Awake(); // 0x003A92B0-0x003A9770
		public override void UpdateKinematicActor(float dt); // 0x003A9770-0x003A9930
		public override string ToString(); // 0x003A9EB0-0x003AA180
		private void SetTargets(); // 0x003A9930-0x003A9B60
		private void CalculatePosition(); // 0x003A9B60-0x003A9D10
		private void CalculateRotation(); // 0x003A9D10-0x003A9EB0
	}

	[Serializable]
	public class PlatformNode // TypeDefIndex: 3166
	{
		// Fields
		public Vector3 position; // 0x10
		public Vector3 eulerAngles; // 0x1C
		public AnimationCurve movementCurve; // 0x28
		public AnimationCurve rotationCurve; // 0x30
		public float targetTime; // 0x38

		// Constructors
		public PlatformNode(); // 0x003B70A0-0x003B71D0
	}

	[Serializable]
	public class RotationAction // TypeDefIndex: 3167
	{
		// Fields
		[SerializeField] // 0x002559B0-0x002559C0
		private bool enabled; // 0x10
		[SerializeField] // 0x002559C0-0x002559D0
		private bool infiniteDuration; // 0x11
		[SerializeField] // 0x002559D0-0x002559E0
		private float cycleDuration; // 0x14
		[SerializeField] // 0x002559E0-0x002559F0
		private bool waitAtTheEnd; // 0x18
		[SerializeField] // 0x002559F0-0x00255A00
		private float waitDuration; // 0x1C
		[SerializeField] // 0x00255A00-0x00255A10
		private Vector3 direction; // 0x20
		[SerializeField] // 0x00255A10-0x00255A20
		private float speed; // 0x2C
		[SerializeField] // 0x00255A20-0x00255A30
		private Transform pivotObject; // 0x30
		private Vector3 actionVector; // 0x38
		private float time; // 0x44
		private bool isWaiting; // 0x48

		// Constructors
		public RotationAction(); // 0x003C0C60-0x003C0D70

		// Methods
		public void Tick(float dt, ref Vector3 position, ref Quaternion rotation); // 0x003C0480-0x003C0850
		private void RotateAround(ref Vector3 position, ref Quaternion rotation, float dt); // 0x003C0850-0x003C0C60
	}
}

namespace Lightbug.CharacterControllerPro.Demo
{
	public abstract class AddTorque : MonoBehaviour // TypeDefIndex: 3168
	{
		// Fields
		[SerializeField] // 0x00255A30-0x00255A40
		protected Vector3 torque; // 0x18
		[SerializeField] // 0x00255A40-0x00255A50
		protected float maxAngularVelocity; // 0x24

		// Constructors
		protected AddTorque(); // 0x00406930-0x00406980

		// Methods
		protected virtual void Awake(); // 0x00406900-0x00406910
		protected abstract void AddTorqueToRigidbody();
		private void FixedUpdate(); // 0x00406910-0x00406930
	}

	public class AddTorque2D : AddTorque // TypeDefIndex: 3169
	{
		// Fields
		private Rigidbody2D rigidbody; // 0x28

		// Constructors
		public AddTorque2D(); // 0x00406B30-0x00406B80

		// Methods
		protected override void Awake(); // 0x00406980-0x004069C0
		protected override void AddTorqueToRigidbody(); // 0x004069C0-0x00406B30
	}

	public class AddTorque3D : AddTorque // TypeDefIndex: 3170
	{
		// Fields
		private Rigidbody rigidbody; // 0x28

		// Constructors
		public AddTorque3D(); // 0x00406C90-0x00406CE0

		// Methods
		protected override void Awake(); // 0x00406B80-0x00406C20
		protected override void AddTorqueToRigidbody(); // 0x00406C20-0x00406C90
	}

	[Serializable]
	public class CharacterReferenceObject // TypeDefIndex: 3171
	{
		// Fields
		public Transform referenceTransform; // 0x10
		public CharacterOrientationMode gravityMode; // 0x18
		public GravityCenterMode gravityCenterMode; // 0x1C
		public bool useNegativeUpAsGravity; // 0x20
		public Transform gravityCenter; // 0x28

		// Constructors
		public CharacterReferenceObject(); // 0x004267A0-0x004267B0
	}

	public class DemoSceneManager : MonoBehaviour // TypeDefIndex: 3172
	{
		// Fields
		[SerializeField] // 0x00255A50-0x00255A60
		private CharacterActor playerCharacterActor; // 0x18
		[SerializeField] // 0x00255A60-0x00255A70
		private CharacterReferenceObject[] references; // 0x20
		[SerializeField] // 0x00255A70-0x00255A80
		private Canvas infoCanvas; // 0x28
		[SerializeField] // 0x00255A80-0x00255A90
		private bool hideAndConfineCursor; // 0x30
		[SerializeField] // 0x00255A90-0x00255AA0
		private bool showCapsule; // 0x31
		[SerializeField] // 0x00255AA0-0x00255AB0
		private GameObject capsuleObject; // 0x38
		[SerializeField] // 0x00255AB0-0x00255AC0
		private GameObject graphicsObject; // 0x40
		private Renderer[] capsuleRenderers; // 0x48
		private Renderer[] graphicsRenderers; // 0x50

		// Constructors
		public DemoSceneManager(); // 0x00359320-0x00359370

		// Methods
		private void Awake(); // 0x00358900-0x00358B80
		private void Update(); // 0x00358E60-0x00359150
		private void EnableRenderers(bool showCapsule); // 0x00358B80-0x00358E60
		private void GoTo(CharacterReferenceObject reference); // 0x00359150-0x00359320
	}

	public class FpsCounter : MonoBehaviour // TypeDefIndex: 3173
	{
		// Fields
		[SerializeField] // 0x00255AC0-0x00255AD0
		private float time; // 0x18
		[SerializeField] // 0x00255AD0-0x00255AE0
		private Text text; // 0x20
		[SerializeField] // 0x00255AE0-0x00255AF0
		private bool showOnlyNumbers; // 0x28
		private float result; // 0x2C
		private int samples; // 0x30
		private string output; // 0x38
		private float fps; // 0x40
		private GUIStyle style; // 0x48

		// Properties
		public float Fps { get; } // 0x00362F20-0x00362F30

		// Constructors
		public FpsCounter(); // 0x00363270-0x00363320

		// Methods
		private void Awake(); // 0x00362F30-0x00363000
		private void Update(); // 0x00363000-0x00363270
	}

	public abstract class GravityModifier : MonoBehaviour // TypeDefIndex: 3174
	{
		// Fields
		[SerializeField] // 0x00255AF0-0x00255B00
		private CharacterReferenceObject reference; // 0x18
		[SerializeField] // 0x00255B00-0x00255B10
		private float waitTime; // 0x20
		protected bool isReady; // 0x24
		private float time; // 0x28
		protected Dictionary<Transform, CharacterActor> characters; // 0x30

		// Constructors
		protected GravityModifier(); // 0x00366320-0x003663F0

		// Methods
		private void Update(); // 0x00365FF0-0x00366070
		protected void ChangeGravitySettings(CharacterActor characterActor); // 0x00366070-0x00366180
		protected CharacterActor GetCharacter(Transform objectTransform); // 0x00366180-0x00366320
	}

	public class GravityModifier2D : GravityModifier // TypeDefIndex: 3175
	{
		// Constructors
		public GravityModifier2D(); // 0x00366550-0x00366620

		// Methods
		private void OnTriggerEnter2D(Collider2D other); // 0x003663F0-0x00366550
	}

	public class GravityModifier3D : GravityModifier // TypeDefIndex: 3176
	{
		// Constructors
		public GravityModifier3D(); // 0x00366780-0x00366850

		// Methods
		private void OnTriggerEnter(Collider other); // 0x00366620-0x00366780
	}

	public class LookAtTarget : MonoBehaviour // TypeDefIndex: 3177
	{
		// Fields
		[SerializeField] // 0x00255B10-0x00255B20
		private Transform target; // 0x18
		[SerializeField] // 0x00255B20-0x00255B30
		private bool invertForwardDirection; // 0x20

		// Constructors
		public LookAtTarget(); // 0x0036BF50-0x0036BFA0

		// Methods
		private void Start(); // 0x0036BCD0-0x0036BE00
		private void Update(); // 0x0036BE00-0x0036BF50
	}

	public class MainMenuManager : MonoBehaviour // TypeDefIndex: 3178
	{
		// Fields
		private string mainMenuName; // 0x18
		private static MainMenuManager instance; // 0x00

		// Properties
		public static MainMenuManager Instance { get; } // 0x00372480-0x003724B0

		// Constructors
		public MainMenuManager(); // 0x003729F0-0x00372A60

		// Methods
		private void Awake(); // 0x003724B0-0x00372730
		public void QuitApplication(); // 0x00372730-0x00372770
		public void GoToScene(string sceneName); // 0x00372770-0x00372860
		private void Update(); // 0x00372860-0x003729F0
	}

	public class MenuButton : MonoBehaviour, IPointerClickHandler, IEventSystemHandler, IPointerEnterHandler, IPointerExitHandler // TypeDefIndex: 3179
	{
		// Fields
		[SerializeField] // 0x00255B30-0x00255B40
		private string sceneName; // 0x18
		[SerializeField] // 0x00255B40-0x00255B50
		private Color highlightColor; // 0x20
		[SerializeField] // 0x00255B50-0x00255B60
		private float lerpSpeed; // 0x30
		private Color normalColor; // 0x34
		private Image image; // 0x48
		private bool enter; // 0x50

		// Constructors
		public MenuButton(); // 0x003733F0-0x00373470

		// Methods
		private void Awake(); // 0x00372F30-0x00373050
		private void Update(); // 0x00373050-0x003732A0
		public void OnPointerClick(PointerEventData eventData); // 0x003732A0-0x003733D0
		public void OnPointerEnter(PointerEventData eventData); // 0x003733D0-0x003733E0
		public void OnPointerExit(PointerEventData eventData); // 0x003733E0-0x003733F0
	}

	public class PerformanceDemoManager : MonoBehaviour // TypeDefIndex: 3180
	{
		// Fields
		[SerializeField] // 0x00255B60-0x00255B70
		private GameObject characterPrefab; // 0x18
		[SerializeField] // 0x00255B70-0x00255B80
		private Transform prefabInstantiationReference; // 0x20
		[SerializeField] // 0x00255B80-0x00255B90
		private Text textField; // 0x28
		[SerializeField] // 0x00255B90-0x00255BA0
		private float maxInstantiationDistance; // 0x30
		private int numberOfCharacters; // 0x34
		private List<GameObject> characterObjects; // 0x38

		// Constructors
		public PerformanceDemoManager(); // 0x003B3C50-0x003B3CF0

		// Methods
		private void Awake(); // 0x003B3260-0x003B33A0
		public void AddCharacters(int numberOfCharacters); // 0x003B33A0-0x003B3A80
		public void RemoveCharacters(); // 0x003B3A80-0x003B3C50
	}
}

namespace Lightbug.CharacterControllerPro.Core
{
	public enum CharacterOrientationMode // TypeDefIndex: 3181
	{
		FixedDirection = 0,
		GravityCenter = 1
	}

	public enum GravityCenterMode // TypeDefIndex: 3182
	{
		Towards = 0,
		Away = 1
	}

	[RequireComponent] // 0x00254E10-0x00254E50
	public class CharacterActor : MonoBehaviour // TypeDefIndex: 3183
	{
		// Fields
		[SerializeField] // 0x00255BA0-0x00255BB0
		private bool showGizmos; // 0x18
		[SerializeField] // 0x00255BB0-0x00255BC0
		protected CharacterTagsAndLayersProfile tagsAndLayersProfile; // 0x20
		[SerializeField] // 0x00255BC0-0x00255BD0
		protected float slopeLimit; // 0x28
		[SerializeField] // 0x00255BD0-0x00255BE0
		private bool detectSteps; // 0x2C
		[SerializeField] // 0x00255BE0-0x00255BF0
		protected float stepOffset; // 0x30
		[SerializeField] // 0x00255BF0-0x00255C00
		protected float stepDownDistance; // 0x34
		[SerializeField] // 0x00255C00-0x00255C10
		private bool edgeCompensation; // 0x38
		[SerializeField] // 0x00255C10-0x00255C20
		private bool alwaysNotGrounded; // 0x39
		[SerializeField] // 0x00255C20-0x00255C30
		private float sizeChangeLerpSpeed; // 0x3C
		[SerializeField] // 0x00255C30-0x00255C40
		protected CharacterOrientationMode orientationMode; // 0x40
		[SerializeField] // 0x00255C40-0x00255C50
		protected Vector3 worldGravityDirection; // 0x44
		[SerializeField] // 0x00255C50-0x00255C60
		protected Transform gravityCenter; // 0x50
		[SerializeField] // 0x00255C60-0x00255C70
		protected GravityCenterMode gravityCenterMode; // 0x58
		[SerializeField] // 0x00255C70-0x00255C80
		protected bool supportDynamicGround; // 0x5C
		[SerializeField] // 0x00255C80-0x00255C90
		private bool rotateForwardDirection; // 0x5D
		private CharacterBody characterBody; // 0x60
		private CharacterActorBehaviour characterActorBehaviour; // 0x68
		private PhysicsComponent physicsComponent; // 0x70
		private bool wasGrounded; // 0x78
		private bool wasStable; // 0x79
		protected CharacterCollisionInfo characterCollisionInfo; // 0x80
		protected DynamicGroundInfo dynamicGroundInfo; // 0x128
		private Dictionary<Transform, KinematicPlatform> kinematicPlatforms; // 0x158
		protected Vector2 currentBodySize; // 0x160
		private Vector2 targetBodySize; // 0x168
		private Vector3 inputVelocity; // 0x170
		private Vector3 rigidbodyStaticVelocity; // 0x17C
		private CharacterGraphics characterGraphics; // 0x188
		private RigidbodyConstraints initialRigidbodyConstraints; // 0x190
		private Vector3 currentGravityDirection; // 0x194
		private List<Contact> collisionResponseContacts; // 0x1A0
		private Vector3 forwardDirection; // 0x1A8
		private Action OnTriggerEnter; // 0x1B8
		private Action OnTriggerExit; // 0x1C0
		private Action<CollisionInfo> OnHeadHit; // 0x1C8
		private Action<CollisionInfo> OnWallHit; // 0x1D0
		private Action<Vector3, Quaternion> OnTeleport; // 0x1D8
		private Action<Vector3, float> OnStepUp; // 0x1E0
		private Action<Vector3> OnGroundedStateEnter; // 0x1E8
		private Action OnGroundedStateExit; // 0x1F0
		private bool teleportFlag; // 0x1F8
		private Vector3 teleportPosition; // 0x1FC
		private Quaternion teleportRotation; // 0x208
		private Vector3 dynamicGroundDisplacement; // 0x218
		private bool stepUpPhases; // 0x224
		private Vector3 targetStepUpPosition; // 0x228
		private Vector3 targetPosition; // 0x234
		private bool forceNotGroundedFlag; // 0x240

		// Properties
		public CharacterBody CharacterBody { get; } // 0x0040F1E0-0x0040F2E0
		public CharacterActorBehaviour CharacterActorBehaviour { get; } // 0x0040F2E0-0x0040F3E0
		public PhysicsComponent PhysicsComponent { get; } // 0x0040F3E0-0x0040F3F0
		public bool IsOnEdge { get; } // 0x0040F3F0-0x0040F400
		public bool IsGrounded { get; } // 0x0040F400-0x0040F4F0
		public float GroundSlopeAngle { get; } // 0x0040F4F0-0x0040F500
		public Vector3 GroundContactPoint { get; } // 0x0040F500-0x0040F520
		public Vector3 GroundContactNormal { get; } // 0x0040F520-0x0040F540
		public Vector3 GroundStableNormal { get; } // 0x0040F540-0x0040F560
		public GameObject GroundObject { get; } // 0x0040F560-0x0040F570
		public Transform GroundTransform { get; } // 0x0040F570-0x0040F5D0
		public Collider2D GroundCollider2D { get; } // 0x0040F5D0-0x0040F5E0
		public Collider GroundCollider3D { get; } // 0x0040F5E0-0x0040F5F0
		public GameObject CurrentTrigger { get; } // 0x0040F5F0-0x0040F650
		public List<GameObject> Triggers { get; } // 0x0040F650-0x0040F670
		public bool WallCollision { get; } // 0x0040F670-0x0040F680
		public float WallAngle { get; } // 0x0040F680-0x0040F690
		public GameObject WallObject { get; } // 0x0040F690-0x0040F6A0
		public Vector3 WallContactPoint { get; } // 0x0040F6A0-0x0040F6C0
		public Vector3 WallContactNormal { get; } // 0x0040F6C0-0x0040F6E0
		public bool IsStable { get; } // 0x0040F6E0-0x0040F7E0
		public bool IsOnUnstableGround { get; } // 0x0040F7E0-0x0040F8E0
		public bool WasGrounded { get; } // 0x0040F8E0-0x0040F8F0
		public bool WasStable { get; } // 0x0040F8F0-0x0040F900
		public bool IsWallARigidbody { get; } // 0x0040F900-0x0040FA10
		public bool IsWallAKinematicRigidbody { get; } // 0x0040FA10-0x0040FAC0
		public bool IsGroundARigidbody { get; } // 0x0040FAC0-0x0040FBD0
		public bool IsGroundAKinematicRigidbody { get; } // 0x0040FBD0-0x0040FC80
		public Vector3 DynamicGroundPointVelocity { get; } // 0x0040FC80-0x0040FD70
		public bool AlwaysNotGrounded { get; set; } // 0x00412970-0x00412980 0x00412980-0x00412990
		public Vector2 DefaultBodySize { get; } // 0x00412990-0x004129B0
		public Vector2 BodySize { get; } // 0x004129B0-0x004129C0
		public LayerMask StaticObstaclesLayerMask { get; } // 0x004129C0-0x004129E0
		public LayerMask DynamicRigidbodiesLayerMask { get; } // 0x004129E0-0x00412A00
		public LayerMask DynamicGroundLayerMask { get; } // 0x00412A00-0x00412A20
		public CharacterTagsAndLayersProfile TagsAndLayersProfile { get; } // 0x00412A20-0x00412A30
		public Vector3 InputVelocity { get; } // 0x00412A30-0x00412A50
		public Vector3 LocalInputVelocity { get; } // 0x00412A50-0x00412B30
		public Vector3 RigidbodyVelocity { get; } // 0x00412BF0-0x00412C20
		public Vector3 RigidbodyStaticVelocity { get; } // 0x00412C40-0x00412C60
		public Vector3 CurrentGravityDirection { get; } // 0x00415CC0-0x00415CE0
		public Transform GravityCenter { get; } // 0x00416030-0x00416040
		public Vector3 Position { get; set; } // 0x0040CA90-0x0040CAC0 0x00416040-0x00416070
		public Quaternion Rotation { get; set; } // 0x00416070-0x004160A0 0x004160A0-0x004160D0
		public Vector3 RigidbodyUp { get; } // 0x00412D30-0x00412D50
		public Vector3 RigidbodyForward { get; } // 0x004160D0-0x00416300
		public Vector3 RigidbodyRight { get; } // 0x00416300-0x00416530
		public RigidbodyComponent RigidbodyComponent { get; } // 0x00412C20-0x00412C40
		public ColliderComponent ColliderComponent { get; } // 0x00415CF0-0x00415D10
		public List<Contact> Contacts { get; } // 0x00416530-0x00416630
		public List<Contact> CollisionResponseContacts { get; } // 0x00416630-0x00416720
		public Vector3 UpDirection { get; } // 0x0040CAC0-0x0040CAE0
		public Vector3 ForwardDirection { get; } // 0x00416BD0-0x00416BF0
		public Vector3 RightDirection { get; } // 0x00416BF0-0x00416CE0
		public Vector3 TargetPosition { get; } // 0x0041C2F0-0x0041C310

		// Events
		public event Action OnTriggerEnter {{
			add; // 0x0041B8C0-0x0041B960
			remove; // 0x0041B960-0x0041BA00
		}
		public event Action OnTriggerExit {{
			add; // 0x0041BA00-0x0041BAA0
			remove; // 0x0041BAA0-0x0041BB40
		}
		public event Action<CollisionInfo> OnHeadHit {{
			add; // 0x0041BB40-0x0041BBE0
			remove; // 0x0041BBE0-0x0041BC80
		}
		public event Action<CollisionInfo> OnWallHit {{
			add; // 0x0041BC80-0x0041BD20
			remove; // 0x0041BD20-0x0041BDC0
		}
		public event Action<Vector3, Quaternion> OnTeleport {{
			add; // 0x0041BDC0-0x0041BE60
			remove; // 0x0041BE60-0x0041BF00
		}
		public event Action<Vector3, float> OnStepUp {{
			add; // 0x004147A0-0x00414840
			remove; // 0x00414B30-0x00414BD0
		}
		public event Action<Vector3> OnGroundedStateEnter {{
			add; // 0x0041BF00-0x0041BFA0
			remove; // 0x0041BFA0-0x0041C040
		}
		public event Action OnGroundedStateExit {{
			add; // 0x0041C040-0x0041C0E0
			remove; // 0x0041C0E0-0x0041C180
		}

		// Constructors
		public CharacterActor(); // 0x0041EE90-0x0041F1B0

		// Methods
		public override string ToString(); // 0x0040FD70-0x00412970
		public void SetInputVelocity(Vector3 inputVelocity); // 0x00412B30-0x00412B40
		public void AddInputVelocity(Vector3 inputVelocity); // 0x00412B40-0x00412BF0
		protected Vector3 GetCenter(Vector3 position); // 0x00412C60-0x00412D30
		protected Vector3 GetTop(Vector3 position); // 0x00412D50-0x00412E10
		protected Vector3 GetBottom(Vector3 position); // 0x00412E10-0x00412EB0
		protected Vector3 GetTopCenter(Vector3 position); // 0x00412EB0-0x00412F90
		protected Vector3 GetTopCenter(Vector3 position, Vector2 bodySize); // 0x00412F90-0x00413070
		protected Vector3 GetBottomCenter(Vector3 position); // 0x00413070-0x00413140
		protected Vector3 GetBottomCenter(Vector3 position, Vector2 bodySize); // 0x00413140-0x00413200
		protected Vector3 GetBottomCenterToTopCenter(); // 0x00413200-0x004132B0
		protected Vector3 GetBottomCenterToTopCenter(Vector2 bodySize); // 0x004132B0-0x00413360
		protected Vector3 GetOffsettedBottomCenter(Vector3 position); // 0x00413360-0x00413420
		private void Awake(); // 0x00413420-0x00413C90
		protected virtual void OnEnable(); // 0x004144E0-0x004147A0
		protected virtual void OnDisable(); // 0x00414840-0x00414B30
		private void ResetParameters(); // 0x00414BD0-0x00414C70
		protected virtual void ApplyWeight(Vector3 contactPoint); // 0x00414C70-0x00415320
		protected virtual void ProcessDynamicGround(ref Vector3 position, float dt); // 0x00415320-0x00415850
		private void FindAndUpdateDynamicGround(Transform groundTransform, Vector3 footPosition); // 0x00415850-0x00415A30
		protected virtual void UpdateDynamicGround(Vector3 position); // 0x00415A30-0x00415C80
		public void SetWorldGravityDirection(Vector3 gravityDirection); // 0x00415C80-0x00415CB0
		public void SetGravityMode(CharacterOrientationMode gravityMode); // 0x00415CB0-0x00415CC0
		public void SetGravityCenter(Transform gravityCenter, GravityCenterMode gravityCenterMode = GravityCenterMode.Towards /* Metadata: 0x0015AF75 */); // 0x00415CE0-0x00415CF0
		private void SetColliderSize(); // 0x00413EC0-0x00414110
		private void RotateCharacter(Vector3 up); // 0x00415D10-0x00416030
		private void HandleRotation(float dt); // 0x00416720-0x00416BD0
		public void SetForwardDirection(Vector3 forwardDirection); // 0x00414110-0x004144E0
		private void GetNewestContacts(); // 0x00416CE0-0x00417280
		public void UpdateCharacter(float dt); // 0x00417280-0x00417720
		private void HandleSize(Vector3 position, float dt); // 0x0041B4E0-0x0041B640
		public void IgnoreLayerMask(bool ignore, LayerMask layerMask); // 0x0041B640-0x0041B7B0
		public void IgnoreLayer(int ignoredLayer, bool ignore); // 0x0041B7B0-0x0041B880
		private void OnTriggerEnterMethod(GameObject trigger); // 0x0041B880-0x0041B8A0
		private void OnTriggerExitMethod(GameObject trigger); // 0x0041B8A0-0x0041B8C0
		public void Teleport(Transform reference); // 0x0041C180-0x0041C260
		public void Teleport(Vector3 position, Quaternion rotation); // 0x0041C260-0x0041C290
		private void HandleTeleportation(); // 0x00417720-0x00417A00
		private void HandlePosition(ref Vector3 position, ref Vector3 initialPosition, Vector3 displacement, float dt); // 0x00417CF0-0x004183E0
		private void OnStepUpMethod(Vector3 position, float stepUpHeight); // 0x0041C2C0-0x0041C2F0
		private void GroundedMovement(ref Vector3 position, ref Vector3 initialPosition, Vector3 displacement, ref bool stepUpResult); // 0x004183E0-0x004185F0
		private void NotGroundedMovement(ref Vector3 position, ref Vector3 initialPosition, Vector3 displacement); // 0x004185F0-0x00418920
		private void NotGroundedPlanarMovement(ref Vector3 position, ref Vector3 initialPosition, Vector3 planarDisplacement); // 0x0041C310-0x0041C380
		private void NotGroundedVerticalMovement(ref Vector3 position, Vector3 verticalDisplacement); // 0x00418920-0x00418E20
		private void SetWallCollisionInfo(CollisionInfo collisionInfo); // 0x0041C380-0x0041C7B0
		private void SetGroundCollisionInfo(CollisionInfo collisionInfo); // 0x00419450-0x00419990
		private bool CheckForGround(out CollisionInfo collisionInfo, Vector3 footPosition, bool grounded, LayerMask layerMask); // 0x0041ACE0-0x0041B000
		protected bool CheckForStableGround(out CollisionInfo collisionInfo, Vector3 footPosition, Vector3 direction, LayerMask layerMask); // 0x0041B000-0x0041B2E0
		protected bool CastBody(out CollisionInfo collisionInfo, Vector3 footPosition, Vector3 displacement, bool grounded, LayerMask layerMask); // 0x0041C7B0-0x0041CCC0
		protected bool CastBodyVertically(out CollisionInfo collisionInfo, Vector3 footPosition, float verticalComponent, LayerMask layerMask); // 0x00418E20-0x00419450
		public bool CheckOverlapWithLayerMask(Vector3 footPosition, LayerMask layerMask); // 0x0041CCC0-0x0041CE90
		private bool CheckTargetBodySize(Vector3 position); // 0x00417A00-0x00417CF0
		private void ProbeGround(ref Vector3 position, bool grounded); // 0x0041A140-0x0041ACE0
		private void EdgeCompensation(ref Vector3 position); // 0x0041B2E0-0x0041B4E0
		public void SetTargetBodySize(Vector2 targetBodySize); // 0x0041CEB0-0x0041CEC0
		private void ForceNotGroundedInternal(); // 0x0041C290-0x0041C2C0
		public void ForceNotGrounded(); // 0x0041CEC0-0x0041CED0
		private bool IsAStableEdge(CollisionInfo collisionInfo); // 0x0041CE90-0x0041CEB0
		private bool IsAnUnstableEdge(CollisionInfo collisionInfo); // 0x0041CED0-0x0041CEF0
		private bool IsValidForStepUp(CollisionInfo collisionInfo); // 0x0041CEF0-0x0041CFF0
		protected virtual void CollideAndSlide(ref Vector3 position, ref Vector3 initialPosition, Vector3 displacement, Vector3 groundPlaneNormal, ref bool stepUpResult); // 0x0041CFF0-0x0041DA10
		protected virtual void CollideAndSlide(ref Vector3 position, ref Vector3 initialPosition, Vector3 displacement, Vector3 groundPlaneNormal); // 0x0041E750-0x0041EC70
		private bool UpdateSlidingPlanes(int iteration, bool stepUpResult, CollisionInfo collisionInfo, ref Vector3 slidingPlaneNormal, ref Vector3 groundPlaneNormal, ref Vector3 displacement); // 0x0041E0F0-0x0041E750
		private bool StepUp(ref Vector3 position, ref Vector3 displacement, out CollisionInfo stepUpResultInfo); // 0x0041DA10-0x0041E0F0
		private bool StepUpShrink(ref Vector3 position, ref Vector3 displacement, out CollisionInfo stepUpResultInfo); // 0x0041EC70-0x0041EE90
		private void UpdateCollisionInfo(out CollisionInfo collisionInfo, HitInfo hitInfo, Vector3 castDisplacement, float skin, LayerMask layerMask); // 0x00419990-0x00419C70
		private void UpdateEdgeInfo(ref CollisionInfo collisionInfo, LayerMask layerMask); // 0x00419C70-0x0041A140
	}

	public abstract class CharacterActorBehaviour : MonoBehaviour // TypeDefIndex: 3184
	{
		// Fields
		protected CharacterActor characterActor; // 0x18

		// Properties
		public CharacterActor CharacterActor { get; } // 0x0041F1B0-0x0041F1C0

		// Constructors
		protected CharacterActorBehaviour(); // 0x0041F1D0-0x0041F210

		// Methods
		public virtual void Initialize(CharacterActor characterActor); // 0x0041F1C0-0x0041F1D0
		public abstract void UpdateBehaviour(float dt);
	}

	public enum CharacterBodyType // TypeDefIndex: 3185
	{
		Sphere = 0,
		Capsule = 1
	}

	public class CharacterBody : MonoBehaviour // TypeDefIndex: 3186
	{
		// Fields
		[SerializeField] // 0x00255C90-0x00255CA0
		private bool is2D; // 0x18
		[SerializeField] // 0x00255CA0-0x00255CB0
		private CharacterBodyType bodyType; // 0x1C
		[SerializeField] // 0x00255CB0-0x00255CC0
		private Vector2 bodySize; // 0x20
		[SerializeField] // 0x00255CC0-0x00255CD0
		private float mass; // 0x28
		private RigidbodyComponent rigidbodyComponent; // 0x30
		private ColliderComponent colliderComponent; // 0x38

		// Properties
		public bool Is2D { get; } // 0x00420D50-0x00420D60
		public RigidbodyComponent RigidbodyComponent { get; } // 0x00420D60-0x00420D70
		public ColliderComponent ColliderComponent { get; } // 0x00420D70-0x00420D80
		public float Mass { get; } // 0x00420D80-0x00420D90
		public Vector2 BodySize { get; } // 0x00420D90-0x00420DA0
		public CharacterBodyType BodyType { get; } // 0x00420DA0-0x00420DB0

		// Constructors
		public CharacterBody(); // 0x00420DB0-0x00420E10

		// Methods
		public void Initialize(); // 0x00413C90-0x00413EC0
	}

	public struct CharacterCollisionInfo // TypeDefIndex: 3187
	{
		// Fields
		public Vector3 groundContactPoint; // 0x00
		public Vector3 groundContactNormal; // 0x0C
		public Vector3 groundStableNormal; // 0x18
		public float stableSlopeAngle; // 0x24
		public bool isOnEdge; // 0x28
		public float edgeAngle; // 0x2C
		public bool wallCollision; // 0x30
		public Vector3 wallContactPoint; // 0x34
		public Vector3 wallContactNormal; // 0x40
		public float wallAngle; // 0x4C
		public GameObject wallObject; // 0x50
		public Collider wallCollider3D; // 0x58
		public Collider2D wallCollider2D; // 0x60
		public Rigidbody wallRigidbody3D; // 0x68
		public Rigidbody2D wallRigidbody2D; // 0x70
		public GameObject groundObject; // 0x78
		public int groundLayer; // 0x80
		public Collider groundCollider3D; // 0x88
		public Collider2D groundCollider2D; // 0x90
		public Rigidbody groundRigidbody3D; // 0x98
		public Rigidbody2D groundRigidbody2D; // 0xA0

		// Methods
		public void Reset(); // 0x00257450-0x00257460
		public void ResetGroundInfo(); // 0x00257460-0x00257470
		public void ResetWallInfo(); // 0x00257470-0x00257680
	}

	public class CharacterDebug : MonoBehaviour // TypeDefIndex: 3188
	{
		// Fields
		[SerializeField] // 0x00255CD0-0x00255CE0
		private Text text; // 0x18
		[SerializeField] // 0x00255CE0-0x00255CF0
		private CharacterActor characterMotor; // 0x20
		[SerializeField] // 0x00255CF0-0x00255D00
		private bool debugCollisionFlags; // 0x28
		[SerializeField] // 0x00255D00-0x00255D10
		private bool debugEvents; // 0x29
		private float time; // 0x2C

		// Constructors
		public CharacterDebug(); // 0x00424080-0x004240D0

		// Methods
		private void Awake(); // 0x00423260-0x00423460
		private void Update(); // 0x00423460-0x00423520
		private void OnEnable(); // 0x00423520-0x00423950
		private void OnDisable(); // 0x00423950-0x00423D80
		private void OnWallHit(CollisionInfo collisionInfo); // 0x00423D80-0x00423DD0
		private void OnEnterGroundedState(Vector3 localVelocity); // 0x00423DD0-0x00423E50
		private void OnExitGroundedState(); // 0x00423E50-0x00423EA0
		private void OnHeadHit(CollisionInfo collisionInfo); // 0x00423EA0-0x00423EF0
		private void OnStepUp(Vector3 position, float stepUpHeight); // 0x00423EF0-0x00423FE0
		private void OnTeleportation(Vector3 position, Quaternion rotation); // 0x00423FE0-0x00424080
	}

	public class CharacterGraphics : MonoBehaviour // TypeDefIndex: 3189
	{
		// Fields
		private const float MaxRotationSlerpSpeed = 40f; // Metadata: 0x0015AF81
		[SerializeField] // 0x00255D10-0x00255D20
		private FacingDirectionMode facingDirectionMode; // 0x18
		[SerializeField] // 0x00255D20-0x00255D30
		private Vector3 rotationOffset; // 0x1C
		[SerializeField] // 0x00255D30-0x00255D40
		private float rotationSmoothness; // 0x28
		[SerializeField] // 0x00255D40-0x00255D50
		private bool scaleAffectedByBodySize; // 0x2C
		private Vector3 positionOffset; // 0x30
		private Vector3 initialScale; // 0x3C
		private Transform characterTransform; // 0x48
		private CharacterActor characterActor; // 0x50
		private GraphicsChild[] childs; // 0x58

		// Nested types
		public enum FacingDirectionMode // TypeDefIndex: 3190
		{
			Rotation = 0,
			Scale = 1
		}

		private struct GraphicsChild // TypeDefIndex: 3191
		{
			// Fields
			public Transform transform; // 0x00
			public Vector3 initialScale; // 0x08
		}

		// Constructors
		public CharacterGraphics(); // 0x00425690-0x00425820

		// Methods
		private void Awake(); // 0x004240D0-0x00424440
		private void Start(); // 0x00424440-0x00424540
		private void OnEnable(); // 0x00424540-0x00424630
		private void OnDisable(); // 0x00424630-0x00424720
		private void OnTeleportation(Vector3 position, Quaternion rotation); // 0x00424720-0x004247D0
		private void Update(); // 0x004247D0-0x00424C90
		private void ScaleByBodySize(); // 0x004255A0-0x00425690
		private void HandleRotation(float dt); // 0x00424C90-0x004255A0
	}

	public class CharacterTagsAndLayersProfile : ScriptableObject // TypeDefIndex: 3192
	{
		// Fields
		public LayerMask staticObstaclesLayerMask; // 0x18
		public LayerMask dynamicGroundLayerMask; // 0x1C
		public LayerMask dynamicRigidbodiesLayerMask; // 0x20
		public string contactRigidbodiesTag; // 0x28

		// Constructors
		public CharacterTagsAndLayersProfile(); // 0x00428A60-0x00428AA0
	}

	public struct CollisionInfo // TypeDefIndex: 3193
	{
		// Fields
		public HitInfo hitInfo; // 0x00
		public bool collision; // 0x58
		public Vector3 displacement; // 0x5C
		public float contactSlopeAngle; // 0x68
		public bool isAnEdge; // 0x6C
		public bool isAStep; // 0x6D
		public Vector3 edgeUpperNormal; // 0x70
		public Vector3 edgeLowerNormal; // 0x7C
		public float edgeUpperSlopeAngle; // 0x88
		public float edgeLowerSlopeAngle; // 0x8C
		public float edgeAngle; // 0x90
	}

	public struct DynamicGroundInfo // TypeDefIndex: 3194
	{
		// Fields
		private Transform transform; // 0x00
		private KinematicPlatform kinematicPlatform; // 0x08
		public Vector3 previousPosition; // 0x10
		public Quaternion previousRotation; // 0x1C

		// Properties
		public Transform Transform { get; } // 0x002293A0-0x002293B0
		public bool IsActive { get; } // 0x002293B0-0x002294A0
		public Vector3 RigidbodyPosition { get; } // 0x002294A0-0x002294B0
		public Quaternion RigidbodyRotation { get; } // 0x002294B0-0x002294C0

		// Methods
		public void Reset(); // 0x00229390-0x002293A0
		public Vector3 GetPointVelocity(Vector3 footPosition); // 0x002294C0-0x002294D0
		public void UpdateTarget(KinematicPlatform kinematicPlatform, Vector3 characterPosition); // 0x002294D0-0x00229530
	}

	public abstract class KinematicActor : MonoBehaviour // TypeDefIndex: 3195
	{
		// Fields
		private RigidbodyComponent rigidbodyComponent; // 0x18

		// Properties
		public RigidbodyComponent RigidbodyComponent { get; } // 0x00368310-0x00368320

		// Constructors
		protected KinematicActor(); // 0x003687E0-0x00368820

		// Methods
		protected virtual void Awake(); // 0x00368320-0x00368770
		public virtual void UpdateKinematicActor(float dt); // 0x00368770-0x00368780
		protected virtual void OnEnable(); // 0x00368780-0x003687B0
		protected virtual void OnDisable(); // 0x003687B0-0x003687E0
	}

	public abstract class KinematicCamera : KinematicActor // TypeDefIndex: 3196
	{
		// Fields
		private bool <InterpolationFlag>k__BackingField; // 0x20

		// Properties
		public bool InterpolationFlag { get; protected set; } // 0x00368820-0x00368830 0x00368830-0x00368840

		// Constructors
		protected KinematicCamera(); // 0x003689F0-0x00368A30

		// Methods
		protected virtual void Start(); // 0x00368840-0x003689F0
	}

	public class KinematicPlatform : KinematicActor // TypeDefIndex: 3197
	{
		// Constructors
		public KinematicPlatform(); // 0x00368BE0-0x00368C20

		// Methods
		protected virtual void Start(); // 0x00368A30-0x00368BE0
	}

	[DefaultExecutionOrder] // 0x00254E50-0x00254E60
	public sealed class SceneController : MonoBehaviour // TypeDefIndex: 3198
	{
		// Fields
		private static SceneController instance; // 0x00
		[SerializeField] // 0x00255D50-0x00255D60
		private bool autoSimulation; // 0x18
		[SerializeField] // 0x00255D60-0x00255D70
		private bool useInterpolation; // 0x19
		private List<CharacterActor> characterActors; // 0x20
		private List<KinematicPlatform> kinematicPlatforms; // 0x28
		private List<KinematicCamera> kinematicCameras; // 0x30
		private Action<float> OnSimulationStart; // 0x38
		private Action<float> OnSimulationEnd; // 0x40
		private Action<float> OnCharacterSimulationStart; // 0x48
		private Action<float> OnCharacterSimulationEnd; // 0x50

		// Properties
		public static SceneController Instance { get; } // 0x003C2340-0x003C2370

		// Events
		public event Action<float> OnSimulationStart {{
			add; // 0x003C23D0-0x003C2460
			remove; // 0x003C2460-0x003C24F0
		}
		public event Action<float> OnSimulationEnd {{
			add; // 0x003C24F0-0x003C2580
			remove; // 0x003C2580-0x003C2610
		}
		public event Action<float> OnCharacterSimulationStart {{
			add; // 0x003C2610-0x003C26A0
			remove; // 0x003C26A0-0x003C2730
		}
		public event Action<float> OnCharacterSimulationEnd {{
			add; // 0x003C2730-0x003C27C0
			remove; // 0x003C27C0-0x003C2850
		}

		// Constructors
		public SceneController(); // 0x003C3270-0x003C3350

		// Methods
		public static void CreateSceneController(); // 0x003C2370-0x003C23D0
		private void Awake(); // 0x003C2850-0x003C29D0
		public void AddActor(CharacterActor characterActor); // 0x003C29D0-0x003C2A20
		public void AddActor(KinematicCamera kinematicCamera); // 0x003C2A20-0x003C2A70
		public void AddActor(KinematicPlatform kinematicPlatform); // 0x003C2A70-0x003C2AC0
		public void RemoveActor(CharacterActor characterActor); // 0x003C2AC0-0x003C2B40
		public void RemoveActor(KinematicCamera kinematicCamera); // 0x003C2B40-0x003C2BC0
		public void RemoveActor(KinematicPlatform kinematicPlatform); // 0x003C2BC0-0x003C2C40
		private void InterpolateRigidbodyComponent(RigidbodyComponent rigidbodyComponent); // 0x003C2C40-0x003C2E50
		private void FixedUpdate(); // 0x003C2E50-0x003C2EA0
		public void Simulate(float dt); // 0x003C2EA0-0x003C3270
	}
}

internal sealed class <PrivateImplementationDetails> // TypeDefIndex: 3199
{
	// Fields
	internal static readonly __StaticArrayInitTypeSize=128 83C803A0255AF38CC9927E0C9D65E3D7EB8FA6E0; // 0x00

	// Nested types
	private struct __StaticArrayInitTypeSize=128 // TypeDefIndex: 3200
	{
	}
}
