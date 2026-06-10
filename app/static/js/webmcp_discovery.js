(function () {
  "use strict";

  const HODLXXI_WEBMCP_TOOLS = [
    {
      name: "hodlxxi_get_agent_descriptor",
      description: "Return the public HODLXXI agent descriptor discovery URL.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false
      },
      execute: async function () {
        return {
          url: "/.well-known/agent.json",
          method: "GET",
          contentType: "application/json"
        };
      }
    },
    {
      name: "hodlxxi_get_agent_capabilities",
      description: "Return the public HODLXXI agent capabilities discovery URL.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false
      },
      execute: async function () {
        return {
          url: "/agent/capabilities",
          method: "GET",
          contentType: "application/json"
        };
      }
    },
    {
      name: "hodlxxi_get_auth_metadata",
      description: "Return the HODLXXI Auth.md and OAuth discovery URLs.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false
      },
      execute: async function () {
        return {
          authMd: "/auth.md",
          authorizationServer: "/.well-known/oauth-authorization-server",
          protectedResource: "/.well-known/oauth-protected-resource"
        };
      }
    },
    {
      name: "hodlxxi_get_mcp_server_card",
      description: "Return the HODLXXI MCP Server Card discovery URL.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false
      },
      execute: async function () {
        return {
          url: "/.well-known/mcp/server-card.json",
          method: "GET",
          contentType: "application/json"
        };
      }
    },
    {
      name: "hodlxxi_get_agent_skills_index",
      description: "Return the HODLXXI Agent Skills discovery index URL.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false
      },
      execute: async function () {
        return {
          url: "/.well-known/agent-skills/index.json",
          method: "GET",
          contentType: "application/json"
        };
      }
    }
  ];

  function provideHodlxxiWebMcpContext() {
    const modelContext = window.navigator && window.navigator.modelContext;

    if (!modelContext || typeof modelContext.provideContext !== "function") {
      return false;
    }

    const context = {
      name: "HODLXXI",
      description: "Bitcoin-native identity and public agent discovery surface.",
      tools: HODLXXI_WEBMCP_TOOLS
    };

    try {
      modelContext.provideContext(context);
      window.__HODLXXI_WEBMCP_REGISTERED__ = true;
      return true;
    } catch (error) {
      window.__HODLXXI_WEBMCP_ERROR__ = String(error && error.message ? error.message : error);
      return false;
    }
  }

  window.HODLXXI_WEBMCP_TOOLS = HODLXXI_WEBMCP_TOOLS;
  window.HODLXXI_PROVIDE_WEBMCP_CONTEXT = provideHodlxxiWebMcpContext;

  provideHodlxxiWebMcpContext();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", provideHodlxxiWebMcpContext, { once: true });
  } else {
    window.setTimeout(provideHodlxxiWebMcpContext, 0);
  }
})();
