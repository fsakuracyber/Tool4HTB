Option Explicit
Dim chars, i, seed, result, pos
chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()*&^%$#@!"
If WScript.Arguments.Count <> 1 Then
  WScript.Echo "usage: predict_vbs_token.vbs SEED"
  WScript.Quit 64
End If
seed = CDbl(WScript.Arguments(0))
result = ""
For i = 1 To 32
  Randomize seed
  pos = Int((Rnd * Len(chars)) + 1)
  result = result & Mid(chars, pos, 1)
Next
WScript.Echo "0:" & result
