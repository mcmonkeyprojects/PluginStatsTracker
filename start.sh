#!/bin/bash
dotnet restore
export ASPNETCORE_ENVIRONMENT=Production
export ASPNETCORE_URLS=http://*:8131
dotnet run
