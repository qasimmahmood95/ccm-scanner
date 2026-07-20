export { CCM_DOMAINS, CCM_DOMAIN_TITLES, CCM_VERSION, domainOfCcmId, isCcmDomain } from "./ccm.js";
export type { CcmDomain } from "./ccm.js";

export { CHECK_ID_PATTERN, checkIdProblem } from "./check-id.js";

export { compareVerdicts, fail, notApplicable, pass, verdictOf } from "./verdict.js";
export type { ControlRef, Evidence, Finding, Status, Verdict } from "./verdict.js";

export { emptyModel, findResource, isUnknown, resourcesOfType } from "./resource.js";
export type { Resource, ResourceModel } from "./resource.js";
