Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
currentDir = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = currentDir

' Iniciar servidor en segundo plano sin ventana negra
WshShell.Run "cmd /c python -m http.server 8000 2>nul || py -m http.server 8000", 0, False

WScript.Sleep 1000

' Abrir navegador predeterminado
WshShell.Run "http://localhost:8000"
