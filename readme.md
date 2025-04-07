# What Is TornadoRoll?

## In Theory  

Tornado is a single-header P2P networking library that provides a high-level C++ abstraction over ENet, focusing on easy peer-to-peer communication with automatic session and connection management, focused on quick implementation for game prototypes, and a middle-ground between control and automation.

## In Reality  

Tornado is a disgusting mountain of code I made in 40 hours on several red bulls for the UNR hackathon. This should ABSOLUTELY NOT be used in any production code or published to an accessible server in its current state. Whenever I add enough security features and documentation to deem this "complete", I'll remove this warning and post a 1.0 version.  

## To Use

Take tornado.hpp. Put it in your sources. Ensure you have [ENet](http://enet.bespin.org/). That's it!  

## To Compile Example

init submodules, then mkdir build, cd into it, and cmake .. && make.
