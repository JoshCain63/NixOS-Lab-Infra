{ pkgs, lib, ... }:
{
  environment.systemPackages = [ pkgs.claude-code ];
}
