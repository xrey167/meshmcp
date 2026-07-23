package orchestrator

import "github.com/xrey167/meshmcp/harness"

// toolLabels maps each catalog tool to the data-flow labels the firewall applies
// to it. The govern middleware attaches these to the GovernedAction so the audit
// record and any label-block rules see the right classification. A tool absent
// here carries no labels (still governed by the allow/deny rule on its name).
var toolLabelMap = map[string][]string{
	// delegation & orchestration
	"task":              {harness.LabelDelegateSpawn},
	"call_agent":        {harness.LabelDelegateSpawn},
	"start_work":        {harness.LabelDelegateSpawn},
	"synthesize":        {harness.LabelDelegateSpawn, harness.LabelNetEgress},
	"background_output": {harness.LabelDelegateRead},
	"background_cancel": {harness.LabelDelegateControl},
	"harness_run":       {harness.LabelDelegateSpawn},
	"harness_status":    {harness.LabelDelegateRead},
	"harness_stop":      {harness.LabelDelegateControl},

	// planning & verification
	"plan":            {harness.LabelPlanWrite},
	"interview":       {harness.LabelPlanWrite},
	"plan_review":     {harness.LabelPlanRead},
	"review_work":     {harness.LabelCodeRead},
	"ultragoal_check": {harness.LabelVerifyRead},

	// code intelligence
	"grep":                {harness.LabelCodeRead},
	"glob":                {harness.LabelCodeRead},
	"edit":                {harness.LabelCodeWrite},
	"lsp_diagnostics":     {harness.LabelCodeRead},
	"lsp_prepare_rename":  {harness.LabelCodeRead},
	"lsp_rename":          {harness.LabelCodeWrite},
	"lsp_goto_definition": {harness.LabelCodeRead},
	"lsp_find_references": {harness.LabelCodeRead},
	"lsp_symbols":         {harness.LabelCodeRead},
	"ast_grep_search":     {harness.LabelCodeRead},
	"ast_grep_replace":    {harness.LabelCodeWrite},
	"look_at":             {harness.LabelMediaRead},

	// sessions & task store
	"session_list":   {harness.LabelSessionRead},
	"session_read":   {harness.LabelSessionRead},
	"session_search": {harness.LabelSessionRead},
	"session_info":   {harness.LabelSessionRead},
	"sessions_send":  {harness.LabelSessionWrite},
	"task_create":    {harness.LabelTaskWrite},
	"task_get":       {harness.LabelTaskRead},
	"task_list":      {harness.LabelTaskRead},
	"task_update":    {harness.LabelTaskWrite},

	// terminal / environment
	"interactive_bash": {harness.LabelExecShell},
	"browser":          {harness.LabelNetEgress, harness.LabelBrowserCtl},
	"canvas":           {harness.LabelCanvasWrite},
	"nodes":            {harness.LabelControlNodes},
	"cron":             {harness.LabelControlCron},

	// skills & market
	"skill":     {harness.LabelSkillRun},
	"skill_mcp": {harness.LabelSkillMCP},
	"market":    {harness.LabelMarket},
}

// toolLabels returns the labels for a tool (nil if none).
func toolLabels(tool string) []string { return toolLabelMap[tool] }
