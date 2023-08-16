<p align="center">
  <img width="100px" src="assets/region.png">
  <br>
  <b>RwxMeme</b>
  <br>
  Injector abusing RWX regions
</p>

## About
This injector abuses the fact that some signed (read whitelisted by anticheat) DLLs have RWX (read, write, execute) sections. Since those sections are writable, running integrity checks towards them does not make sense, so we can simply map our own DLL into those sections.

In order for this to work on protected processes, [another meme is used](https://github.com/SamuelTulach/meme-rw) (EPROCESS->PreviousMode overwritten with vulnerable driver). 

## Usage 
Compile or download the project. Pass the process name, window title and DLL path as process arguments (run without them to get more details). Don't forget that the signed DLL will be visible in the process.
