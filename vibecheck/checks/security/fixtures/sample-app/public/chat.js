import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ apiKey: window.ANTHROPIC_KEY, dangerouslyAllowBrowser: true });
document.getElementById("out").innerHTML = new URLSearchParams(location.search).get("q");
