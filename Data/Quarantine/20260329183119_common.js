/******/ (() => { // webpackBootstrap
/******/ 	// runtime can't be in strict mode because a global variable is assign and maybe created.
/******/ 	var __webpack_modules__ = ({

/***/ "./ts/constants.ts":
/*!*************************!*\
  !*** ./ts/constants.ts ***!
  \*************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ActiveL2ProductsXml: () => (/* binding */ ActiveL2ProductsXml),
/* harmony export */   Attributes: () => (/* binding */ Attributes),
/* harmony export */   CustomChannelConstant: () => (/* binding */ CustomChannelConstant),
/* harmony export */   Entities: () => (/* binding */ Entities),
/* harmony export */   EnvironmentVariableName: () => (/* binding */ EnvironmentVariableName),
/* harmony export */   OpportunityAssignmentConstant: () => (/* binding */ OpportunityAssignmentConstant),
/* harmony export */   OpportunityStatus: () => (/* binding */ OpportunityStatus),
/* harmony export */   OpportunityStatusReason: () => (/* binding */ OpportunityStatusReason),
/* harmony export */   OtpSubSource: () => (/* binding */ OtpSubSource),
/* harmony export */   ProductStructure: () => (/* binding */ ProductStructure),
/* harmony export */   Source: () => (/* binding */ Source),
/* harmony export */   UserGroup: () => (/* binding */ UserGroup),
/* harmony export */   formType: () => (/* binding */ formType),
/* harmony export */   l2ProductsFilterXMLString: () => (/* binding */ l2ProductsFilterXMLString)
/* harmony export */ });
var Entities = {
    OTPProductCondition: "otprccrm_otpproductcondition",
    OTPOpportunityAssignment: "otprccrm_opportunityassignment",
    Opportunity: "opportunity",
    ProductBranchSkill: "otprccrm_product_otprccrm_otpbranchskill",
    BranchBranchSkillNN: "otprccrm_branch_otprccrm_otpbranchskillnn",
    SystemUser: "systemuser",
    Contact: "contact",
    OTPBranch: "otprccrm_branch"
};
var Attributes = {
    Programme: {
        Owner: "otprccrm_ownerid"
    },
    NotificationSubscriber: {
        Subscriber: "otprccrm_subscriber"
    },
    Opportunity: {
        StatusCode: "statuscode",
        StateCode: "statecode",
        estimatedCloseDate: "estimatedclosedate",
        L1Product: "otprccrm_l1product",
        L2Product: "otprccrm_l2product",
        JourneyId: "otprccrm_journeyid",
        SubSource: "otprccrm_subsource",
        Source: "otprccrm_source",
        L1ProductValue: "_otprccrm_l1product_value",
        L2ProductValue: "_otprccrm_l2product_value",
        PrefillError: "otprccrm_prefillerror",
        InvalidCecilId: "otprccrm_invalidcecilid",
        Name: "name"
    },
    Product: {
        EntityName: "product",
        ProductStructure: "productstructure",
        ParentProductId: "parentproductid"
    },
    OpportunityAssignment: {
        Assignee: "otprccrm_assignee",
        Branch: "otprccrm_branch",
        UserGroup: "otprccrm_usergroup",
        Branches: "otprccrm_branchlist"
    },
    ProductBranchSkill: {
        BranchSkillId: "otprccrm_otpbranchskillid"
    },
    SystemUser: {
        MainBranchValue: "_otprccrm_mainbranch_value"
    },
    Journey: {
        PromotionEndDate: "otprccrm_promotionenddate",
        JourneyEndTime: "msdynmkt_journeyendtime"
    }
};
var OpportunityStatusReason = {
    New: 288050001
};
var OpportunityStatus = {
    Active: 0
};
var Source = {
    ManualSource: 1,
    Externalsource: 2
};
var ProductStructure = {
    ProductFamily: 1,
    Product: 2
};
var UserGroup = {
    BranchAdvisor: 1,
    BranchManager: 2,
    MobileBanker: 3,
    MobileBankerManager: 4,
    RegionalManager: 5
};
var OtpSubSource = {
    Branch: 1,
    MobileBanker: 2,
    CC: 3,
    Zenga: 4,
    Ingatlanpont: 5,
    PenzugyPont: 6
};
var formType = {
    Undefined: 0,
    Create: 1,
    Update: 2,
    ReadOnly: 3,
    Disabled: 4,
    BulkEdit: 6
};
var l2ProductsFilterXMLString = "\n<fetch version='1.0' output-format='xml-platform' mapping='logical' distinct='false'>\n  <entity name='product'>\n    <attribute name='name'/>\n    <attribute name='productid'/>\n    <order attribute='productnumber' descending='false'/>\n    <filter type='and'>\n      <condition attribute='productstructure' operator='eq' value='1'/>\n      <condition attribute='parentproductid' operator='eq' uiname='Biztos\u00EDt\u00E1s' uitype='product' value='{l1ProductId}'/>\n    </filter>\n    <link-entity name='product' from='productid' to='parentproductid' visible='false' link-type='outer' alias='a_cfa97162538bf011b4cc6045bdf66e22'>\n      <attribute name='name'/>\n    </link-entity>\n  </entity>\n</fetch>\n";
var ActiveL2ProductsXml = "\n<fetch version='1.0' output-format='xml-platform' mapping='logical' distinct='false'>\n<entity name='product'>\n<attribute name='name'/>\n<attribute name='productid'/>\n<order attribute='productnumber' descending='false'/>\n<filter type='and'>\n<condition attribute='productstructure' operator='eq' value='1'/>\n<condition attribute='statecode' operator='eq' value='2'/>\n</filter>\n</entity>\n</fetch>\n";
var CustomChannelConstant = {
    MailboxChannelDefinitionId: "03da0e32-0585-479a-b1d6-d593da9e6adb",
    BranchChannelDefinitionId: "61e96156-16e8-4ec8-94e9-aaaad01e494d"
};
var OpportunityAssignmentConstant = {
    OpportunityOwnerAssignmentCustomAPI: "otprccrm_opportunityassignmentapi",
    UserGridName: "subgrid_select_user",
    TeamGridName: "subgrid_select_team",
    SidePaneName: "otp_assignment_pane"
};
var EnvironmentVariableName = {
    CecilIDMissingError: "otprccrm_cecilidmissingerror",
    CecilIdInvalidError: "otprccrm_cecilidnotfounderror"
};


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be in strict mode.
(() => {
"use strict";
/*!**********************!*\
  !*** ./ts/common.ts ***!
  \**********************/
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   FormHelper: () => (/* binding */ FormHelper)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./constants */ "./ts/constants.ts");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (undefined && undefined.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};

var FormHelper = /** @class */ (function () {
    function FormHelper() {
    }
    FormHelper.SetCurrentLoggedInUserInLookupField = function (context, fieldName) {
        var setUservalue = new Array();
        setUservalue[0] = new Object();
        setUservalue[0].id = Xrm.Utility.getGlobalContext().userSettings.userId;
        setUservalue[0].entityType = 'systemuser';
        setUservalue[0].name = Xrm.Utility.getGlobalContext().userSettings.userName;
        context.getAttribute(fieldName).setValue(setUservalue);
    };
    FormHelper.Programme_OnloadToSetLoggedInUser = function (context) {
        if (context.getFormContext().ui.getFormType() === _constants__WEBPACK_IMPORTED_MODULE_0__.formType.Create) {
            var formContextCustom = context.getFormContext();
            FormHelper.SetCurrentLoggedInUserInLookupField(formContextCustom, _constants__WEBPACK_IMPORTED_MODULE_0__.Attributes.Programme.Owner);
        }
    };
    /// --------------------------------------------
    /// strip the braces of guid
    /// --------------------------------------------
    FormHelper.stripBraces = function (guid) {
        if (!guid)
            return "";
        return guid.replace("{", "").replace("}", "");
    };
    /// --------------------------------------------
    /// Build query string
    /// --------------------------------------------
    FormHelper.buildQuery = function (params) {
        var _a;
        var parts = [];
        for (var _i = 0, _b = Object.keys(params); _i < _b.length; _i++) {
            var key = _b[_i];
            var value = (_a = params[key]) !== null && _a !== void 0 ? _a : "";
            parts.push("".concat(encodeURIComponent(key), "=").concat(encodeURIComponent(value)));
        }
        return parts.join("&");
    };
    /// --------------------------------------------
    /// Get BSS config code related to product
    /// --------------------------------------------
    FormHelper.getBssConfigurationsFetchXml = function (productId) {
        return __awaiter(this, void 0, void 0, function () {
            var fetchXml, relatedCodes, response, error_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        fetchXml = "\n    <fetch>\n      <entity name=\"otprccrm_bssconfigurations\">\n        <attribute name=\"otprccrm_code\" />\n       <link-entity name=\"otprccrm_product_otprccrm_bssconfigurations\" from=\"otprccrm_bssconfigurationsid\" to=\"otprccrm_bssconfigurationsid\" visible=\"false\" intersect=\"true\">\n      <link-entity name=\"product\" from=\"productid\" to=\"productid\" alias=\"ad\">\n    <filter type=\"and\">\n   <condition attribute=\"productid\" operator=\"eq\" value=\"".concat(productId, "\" />\n  </filter>\n        </link-entity>\n  </link-entity>\n  </entity>\n</fetch>      \n");
                        relatedCodes = [];
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, Xrm.WebApi.retrieveMultipleRecords("otprccrm_bssconfigurations", "?fetchXml=".concat(encodeURIComponent(fetchXml)))];
                    case 2:
                        response = _a.sent();
                        response.entities.forEach(function (entity) {
                            if (entity.otprccrm_code) {
                                relatedCodes.push(entity.otprccrm_code);
                            }
                        });
                        return [3 /*break*/, 4];
                    case 3:
                        error_1 = _a.sent();
                        console.error("Error fetching BSS configurations:", error_1);
                        return [3 /*break*/, 4];
                    case 4: return [2 /*return*/, relatedCodes];
                }
            });
        });
    };
    /// --------------------------------------------
    /// Build appointment configuration
    /// --------------------------------------------
    FormHelper.buildAppointmentConfig = function (relatedCodes) {
        var params = new URLSearchParams();
        var firstDone = false;
        for (var _i = 0, _a = relatedCodes !== null && relatedCodes !== void 0 ? relatedCodes : []; _i < _a.length; _i++) {
            var raw = _a[_i];
            var code = (raw !== null && raw !== void 0 ? raw : "").toString().trim();
            if (!code)
                continue; // skip empties
            if (!firstDone) {
                // 'set' ensures the first value is assigned for the key (replaces if existed)
                params.set("p_appointment_config", code);
                firstDone = true;
            }
            else {
                // subsequent values are appended (repeated key)
                params.append("p_appointment_config", code);
            }
        }
        return params.toString(); // no leading "?"
    };
    /// --------------------------------------------
    /// Get environment variable value from CRM
    /// --------------------------------------------
    FormHelper.getEnvironmentVariables = function (variableNames) {
        var _a;
        return __awaiter(this, void 0, void 0, function () {
            var result, filter, query, response, _i, _b, entity, schemaName, values, err_1;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        result = {};
                        if (!variableNames || variableNames.length === 0) {
                            return [2 /*return*/, result];
                        }
                        filter = variableNames
                            .map(function (v) { return "schemaname eq '".concat(v, "'"); })
                            .join(" or ");
                        query = "?$select=schemaname\n            &$expand=environmentvariabledefinition_environmentvariablevalue($select=value)\n            &$filter=".concat(filter);
                        _c.label = 1;
                    case 1:
                        _c.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, Xrm.WebApi.retrieveMultipleRecords("environmentvariabledefinition", query)];
                    case 2:
                        response = _c.sent();
                        for (_i = 0, _b = response.entities; _i < _b.length; _i++) {
                            entity = _b[_i];
                            schemaName = entity.schemaname;
                            values = entity.environmentvariabledefinition_environmentvariablevalue;
                            if (values && values.length > 0) {
                                result[schemaName] = (_a = values[0].value) !== null && _a !== void 0 ? _a : "";
                            }
                            else {
                                result[schemaName] = "";
                            }
                        }
                        // Mark missing variables
                        variableNames.forEach(function (name) {
                            if (!result.hasOwnProperty(name)) {
                                result[name] = "";
                            }
                        });
                        return [3 /*break*/, 4];
                    case 3:
                        err_1 = _c.sent();
                        console.error("Error fetching environment variables:", err_1);
                        return [3 /*break*/, 4];
                    case 4: return [2 /*return*/, result];
                }
            });
        });
    };
    /// --------------------------------------------
    /// Retrieve contact details (CecilID and fullname)
    /// --------------------------------------------
    FormHelper.retrieveContactDetails = function (customerId) {
        return __awaiter(this, void 0, void 0, function () {
            var contact, cecilId, customerName;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, Xrm.WebApi.retrieveRecord("contact", customerId, "?$select=otprccrm_cecilid,fullname")];
                    case 1:
                        contact = _a.sent();
                        cecilId = contact.otprccrm_cecilid;
                        customerName = contact.fullname;
                        if (!!cecilId) return [3 /*break*/, 3];
                        // Show info but continue (your original code did not return)
                        return [4 /*yield*/, Xrm.Navigation.openAlertDialog({ text: "CecilID not found on related Contact." })];
                    case 2:
                        // Show info but continue (your original code did not return)
                        _a.sent();
                        _a.label = 3;
                    case 3: return [2 /*return*/, { cecilId: cecilId, customerName: customerName }];
                }
            });
        });
    };
    /// --------------------------------------------
    /// Build final URL with query parameters
    /// --------------------------------------------
    FormHelper.buildFinalUrl = function (options) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function () {
            var environmentValues, baseUrl, callbackUrl, rawCallbackUrl, query, finalQuery;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0: return [4 /*yield*/, FormHelper.getEnvironmentVariables([
                            "otprccrm_bsscallbackurl",
                            "otprccrm_bssbaseurl"
                        ])];
                    case 1:
                        environmentValues = _c.sent();
                        baseUrl = environmentValues.otprccrm_bssbaseurl;
                        callbackUrl = environmentValues.otprccrm_bsscallbackurl;
                        rawCallbackUrl = "".concat(callbackUrl, "?opportunityid=").concat(encodeURIComponent(options.opportunityId));
                        query = FormHelper.buildQuery({
                            p_ext_lead_name: options.opportunityName,
                            // TODO: revisit p_ext_lead_details
                            p_ext_lead_details: "Kattints a linkre az érdeklődés részleteiért.",
                            p_ext_lead_url: options.recordUrl,
                            p_caller_system: "RCCRM",
                            p_action: "appointment-ext",
                            p_cecil_system_code: (_a = options.cecilId) !== null && _a !== void 0 ? _a : "",
                            p_customer_name: (_b = options.customerName) !== null && _b !== void 0 ? _b : "",
                            p_ext_data_name: "opportunityid",
                            // REQUIRED
                            p_ext_data_value: options.opportunityId,
                            p_callback_url: rawCallbackUrl,
                            p_callback_target: "_Self",
                            p_callback_method: "GET",
                            p_appointment_code: options.appointmentCode,
                            p_comment_enabled: "Y",
                            p_email_notifier_fl: "Y",
                            p_sms_notification_fl: "Y",
                        });
                        finalQuery = [query, options.queryStringBSSCodes].filter(Boolean).join("&");
                        return [2 /*return*/, "".concat(baseUrl, "?").concat(finalQuery)];
                }
            });
        });
    };
    return FormHelper;
}());


})();

var __webpack_export_target__ = (OTP = typeof OTP === "undefined" ? {} : OTP);
for(var __webpack_i__ in __webpack_exports__) __webpack_export_target__[__webpack_i__] = __webpack_exports__[__webpack_i__];
if(__webpack_exports__.__esModule) Object.defineProperty(__webpack_export_target__, "__esModule", { value: true });
/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29tbW9uLmpzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFFQTtBQUNBO0FBQ0E7QUFFQTtBQUNBO0FBQ0E7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUdBO0FBaUJBO0FBY0E7QUFDQTtBQUNBO0FBQ0E7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7OztBQ3JKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7QUN2QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7QUNQQTs7Ozs7QUNBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ05BO0FBRUE7QUFBQTtBQWlPQTtBQWhPQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFDQTtBQUFBO0FBQ0E7QUFDQTtBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUNBO0FBQ0E7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFFQTtBQUNBO0FBQ0E7QUFFQTs7Ozs7O0FBQ0E7QUFlQTs7OztBQUVBOztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7OztBQUVBOztBQUdBOzs7O0FBQ0E7QUFFQTtBQUNBO0FBQ0E7QUFFQTtBQUNBO0FBQ0E7QUFFQTtBQUFBO0FBQ0E7QUFDQTtBQUFBO0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFDQTtBQUNBO0FBQ0E7Ozs7Ozs7QUFJQTtBQUVBO0FBQ0E7QUFDQTtBQUdBO0FBQ0E7QUFDQTtBQUVBOzs7O0FBS0E7O0FBQUE7QUFLQTtBQUFBO0FBQ0E7QUFDQTtBQUVBO0FBQ0E7QUFDQTtBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7O0FBR0E7O0FBR0E7Ozs7QUFDQTtBQUdBO0FBQ0E7QUFDQTtBQUNBOzs7OztBQUNBOztBQUFBO0FBTUE7QUFDQTtBQUVBO0FBQ0E7QUFDQTs7QUFEQTtBQUNBOztBQUdBOzs7O0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7O0FBVUE7QUFDQTtBQUNBO0FBQUE7O0FBRkE7QUFPQTtBQUVBO0FBQ0E7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUVBO0FBR0E7QUFFQTs7OztBQUNBO0FBRUE7QUFBQSIsInNvdXJjZXMiOlsid2VicGFjazovL09UUC8uL3RzL2NvbnN0YW50cy50cyIsIndlYnBhY2s6Ly9PVFAvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vT1RQL3dlYnBhY2svcnVudGltZS9kZWZpbmUgcHJvcGVydHkgZ2V0dGVycyIsIndlYnBhY2s6Ly9PVFAvd2VicGFjay9ydW50aW1lL2hhc093blByb3BlcnR5IHNob3J0aGFuZCIsIndlYnBhY2s6Ly9PVFAvd2VicGFjay9ydW50aW1lL21ha2UgbmFtZXNwYWNlIG9iamVjdCIsIndlYnBhY2s6Ly9PVFAvLi90cy9jb21tb24udHMiXSwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGNvbnN0IEVudGl0aWVzID0ge1xyXG4gICAgT1RQUHJvZHVjdENvbmRpdGlvbjogXCJvdHByY2NybV9vdHBwcm9kdWN0Y29uZGl0aW9uXCIsXHJcbiAgICBPVFBPcHBvcnR1bml0eUFzc2lnbm1lbnQ6IFwib3RwcmNjcm1fb3Bwb3J0dW5pdHlhc3NpZ25tZW50XCIsXHJcbiAgICBPcHBvcnR1bml0eTogXCJvcHBvcnR1bml0eVwiLFxyXG4gICAgUHJvZHVjdEJyYW5jaFNraWxsOiBcIm90cHJjY3JtX3Byb2R1Y3Rfb3RwcmNjcm1fb3RwYnJhbmNoc2tpbGxcIixcclxuICAgIEJyYW5jaEJyYW5jaFNraWxsTk46IFwib3RwcmNjcm1fYnJhbmNoX290cHJjY3JtX290cGJyYW5jaHNraWxsbm5cIixcclxuICAgIFN5c3RlbVVzZXI6IFwic3lzdGVtdXNlclwiLFxyXG4gICAgQ29udGFjdDogXCJjb250YWN0XCIsXHJcbiAgICBPVFBCcmFuY2g6IFwib3RwcmNjcm1fYnJhbmNoXCJcclxufTtcclxuZXhwb3J0IGNvbnN0IEF0dHJpYnV0ZXMgPSB7XHJcbiAgICBQcm9ncmFtbWU6IHtcclxuICAgICAgICBPd25lcjogXCJvdHByY2NybV9vd25lcmlkXCJcclxuICAgIH0sXHJcbiAgICBOb3RpZmljYXRpb25TdWJzY3JpYmVyOiB7XHJcbiAgICAgICAgU3Vic2NyaWJlcjogXCJvdHByY2NybV9zdWJzY3JpYmVyXCJcclxuICAgIH0sXHJcbiAgICBPcHBvcnR1bml0eToge1xyXG4gICAgICAgIFN0YXR1c0NvZGU6IFwic3RhdHVzY29kZVwiLFxyXG4gICAgICAgIFN0YXRlQ29kZTogXCJzdGF0ZWNvZGVcIixcclxuICAgICAgICBlc3RpbWF0ZWRDbG9zZURhdGU6XCJlc3RpbWF0ZWRjbG9zZWRhdGVcIixcclxuICAgICAgICBMMVByb2R1Y3Q6XCJvdHByY2NybV9sMXByb2R1Y3RcIixcclxuICAgICAgICBMMlByb2R1Y3Q6XCJvdHByY2NybV9sMnByb2R1Y3RcIixcclxuICAgICAgICBKb3VybmV5SWQ6XCJvdHByY2NybV9qb3VybmV5aWRcIixcclxuICAgICAgICBTdWJTb3VyY2U6XCJvdHByY2NybV9zdWJzb3VyY2VcIixcclxuICAgICAgICBTb3VyY2U6XCJvdHByY2NybV9zb3VyY2VcIixcclxuICAgICAgICBMMVByb2R1Y3RWYWx1ZTogXCJfb3RwcmNjcm1fbDFwcm9kdWN0X3ZhbHVlXCIsXHJcbiAgICAgICAgTDJQcm9kdWN0VmFsdWU6IFwiX290cHJjY3JtX2wycHJvZHVjdF92YWx1ZVwiLFxyXG4gICAgICAgIFByZWZpbGxFcnJvcjogXCJvdHByY2NybV9wcmVmaWxsZXJyb3JcIixcclxuICAgICAgICBJbnZhbGlkQ2VjaWxJZDogXCJvdHByY2NybV9pbnZhbGlkY2VjaWxpZFwiLFxyXG4gICAgICAgIE5hbWU6IFwibmFtZVwiXHJcbiAgICB9LFxyXG4gICAgUHJvZHVjdDoge1xyXG4gICAgICAgIEVudGl0eU5hbWU6XCJwcm9kdWN0XCIsXHJcbiAgICAgICAgUHJvZHVjdFN0cnVjdHVyZTogXCJwcm9kdWN0c3RydWN0dXJlXCIsXHJcbiAgICAgICAgUGFyZW50UHJvZHVjdElkOiBcInBhcmVudHByb2R1Y3RpZFwiXHJcbiAgICB9LFxyXG4gICAgT3Bwb3J0dW5pdHlBc3NpZ25tZW50OiB7XHJcbiAgICAgICAgQXNzaWduZWU6IFwib3RwcmNjcm1fYXNzaWduZWVcIixcclxuICAgICAgICBCcmFuY2g6IFwib3RwcmNjcm1fYnJhbmNoXCIsXHJcbiAgICAgICAgVXNlckdyb3VwOiBcIm90cHJjY3JtX3VzZXJncm91cFwiLFxyXG4gICAgICAgIEJyYW5jaGVzOiBcIm90cHJjY3JtX2JyYW5jaGxpc3RcIlxyXG4gICAgfSxcclxuICAgIFByb2R1Y3RCcmFuY2hTa2lsbDoge1xyXG4gICAgICAgIEJyYW5jaFNraWxsSWQ6IFwib3RwcmNjcm1fb3RwYnJhbmNoc2tpbGxpZFwiXHJcbiAgICB9LFxyXG4gICAgU3lzdGVtVXNlcjoge1xyXG4gICAgICAgIE1haW5CcmFuY2hWYWx1ZTogXCJfb3RwcmNjcm1fbWFpbmJyYW5jaF92YWx1ZVwiXHJcbiAgICB9LFxyXG4gICAgSm91cm5leSA6XHJcbiAgICB7XHJcbiAgICAgICAgUHJvbW90aW9uRW5kRGF0ZTogXCJvdHByY2NybV9wcm9tb3Rpb25lbmRkYXRlXCIsXHJcbiAgICAgICAgSm91cm5leUVuZFRpbWU6XCJtc2R5bm1rdF9qb3VybmV5ZW5kdGltZVwiXHJcbiAgICB9XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBPcHBvcnR1bml0eVN0YXR1c1JlYXNvbiA9IHtcclxuICAgIE5ldzogMjg4MDUwMDAxXHJcbn07XHJcblxyXG5leHBvcnQgY29uc3QgT3Bwb3J0dW5pdHlTdGF0dXMgPSB7XHJcbiAgICBBY3RpdmU6IDBcclxufTtcclxuXHJcbmV4cG9ydCBjb25zdCBTb3VyY2U9e1xyXG4gICAgTWFudWFsU291cmNlOjEsXHJcbiAgICBFeHRlcm5hbHNvdXJjZToyXHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBQcm9kdWN0U3RydWN0dXJlID0ge1xyXG4gICAgUHJvZHVjdEZhbWlseTogMSxcclxuICAgIFByb2R1Y3Q6IDJcclxufTtcclxuXHJcbmV4cG9ydCBjb25zdCBVc2VyR3JvdXAgPVxyXG57XHJcbiAgICBCcmFuY2hBZHZpc29yIDogMSxcclxuICAgIEJyYW5jaE1hbmFnZXIgOiAyLFxyXG4gICAgTW9iaWxlQmFua2VyIDogMyxcclxuICAgIE1vYmlsZUJhbmtlck1hbmFnZXIgOiA0LFxyXG4gICAgUmVnaW9uYWxNYW5hZ2VyIDogNVxyXG4gXHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBPdHBTdWJTb3VyY2UgPSB7XHJcbiAgICBCcmFuY2ggOiAxLFxyXG4gICAgTW9iaWxlQmFua2VyOiAyLFxyXG4gICAgQ0M6IDMsXHJcbiAgICBaZW5nYTogNCxcclxuICAgIEluZ2F0bGFucG9udDogNSxcclxuICAgIFBlbnp1Z3lQb250OiA2XHJcbn1cclxuXHJcbmV4cG9ydCBjb25zdCBmb3JtVHlwZSA9IHtcclxuICAgIFVuZGVmaW5lZDogMCxcclxuICAgIENyZWF0ZTogMSxcclxuICAgIFVwZGF0ZTogMixcclxuICAgIFJlYWRPbmx5OiAzLFxyXG4gICAgRGlzYWJsZWQ6IDQsXHJcbiAgICBCdWxrRWRpdDogNlxyXG59O1xyXG5cclxuXHJcbmV4cG9ydCBjb25zdCBsMlByb2R1Y3RzRmlsdGVyWE1MU3RyaW5nOiBzdHJpbmcgPSBgXHJcbjxmZXRjaCB2ZXJzaW9uPScxLjAnIG91dHB1dC1mb3JtYXQ9J3htbC1wbGF0Zm9ybScgbWFwcGluZz0nbG9naWNhbCcgZGlzdGluY3Q9J2ZhbHNlJz5cclxuICA8ZW50aXR5IG5hbWU9J3Byb2R1Y3QnPlxyXG4gICAgPGF0dHJpYnV0ZSBuYW1lPSduYW1lJy8+XHJcbiAgICA8YXR0cmlidXRlIG5hbWU9J3Byb2R1Y3RpZCcvPlxyXG4gICAgPG9yZGVyIGF0dHJpYnV0ZT0ncHJvZHVjdG51bWJlcicgZGVzY2VuZGluZz0nZmFsc2UnLz5cclxuICAgIDxmaWx0ZXIgdHlwZT0nYW5kJz5cclxuICAgICAgPGNvbmRpdGlvbiBhdHRyaWJ1dGU9J3Byb2R1Y3RzdHJ1Y3R1cmUnIG9wZXJhdG9yPSdlcScgdmFsdWU9JzEnLz5cclxuICAgICAgPGNvbmRpdGlvbiBhdHRyaWJ1dGU9J3BhcmVudHByb2R1Y3RpZCcgb3BlcmF0b3I9J2VxJyB1aW5hbWU9J0JpenRvc8OtdMOhcycgdWl0eXBlPSdwcm9kdWN0JyB2YWx1ZT0ne2wxUHJvZHVjdElkfScvPlxyXG4gICAgPC9maWx0ZXI+XHJcbiAgICA8bGluay1lbnRpdHkgbmFtZT0ncHJvZHVjdCcgZnJvbT0ncHJvZHVjdGlkJyB0bz0ncGFyZW50cHJvZHVjdGlkJyB2aXNpYmxlPSdmYWxzZScgbGluay10eXBlPSdvdXRlcicgYWxpYXM9J2FfY2ZhOTcxNjI1MzhiZjAxMWI0Y2M2MDQ1YmRmNjZlMjInPlxyXG4gICAgICA8YXR0cmlidXRlIG5hbWU9J25hbWUnLz5cclxuICAgIDwvbGluay1lbnRpdHk+XHJcbiAgPC9lbnRpdHk+XHJcbjwvZmV0Y2g+XHJcbmA7XHJcbiBcclxuZXhwb3J0IGNvbnN0IEFjdGl2ZUwyUHJvZHVjdHNYbWw6IHN0cmluZyA9IGBcclxuPGZldGNoIHZlcnNpb249JzEuMCcgb3V0cHV0LWZvcm1hdD0neG1sLXBsYXRmb3JtJyBtYXBwaW5nPSdsb2dpY2FsJyBkaXN0aW5jdD0nZmFsc2UnPlxyXG48ZW50aXR5IG5hbWU9J3Byb2R1Y3QnPlxyXG48YXR0cmlidXRlIG5hbWU9J25hbWUnLz5cclxuPGF0dHJpYnV0ZSBuYW1lPSdwcm9kdWN0aWQnLz5cclxuPG9yZGVyIGF0dHJpYnV0ZT0ncHJvZHVjdG51bWJlcicgZGVzY2VuZGluZz0nZmFsc2UnLz5cclxuPGZpbHRlciB0eXBlPSdhbmQnPlxyXG48Y29uZGl0aW9uIGF0dHJpYnV0ZT0ncHJvZHVjdHN0cnVjdHVyZScgb3BlcmF0b3I9J2VxJyB2YWx1ZT0nMScvPlxyXG48Y29uZGl0aW9uIGF0dHJpYnV0ZT0nc3RhdGVjb2RlJyBvcGVyYXRvcj0nZXEnIHZhbHVlPScyJy8+XHJcbjwvZmlsdGVyPlxyXG48L2VudGl0eT5cclxuPC9mZXRjaD5cclxuYDtcclxuXHJcbmV4cG9ydCBjb25zdCBDdXN0b21DaGFubmVsQ29uc3RhbnQgPSB7XHJcbiAgICBNYWlsYm94Q2hhbm5lbERlZmluaXRpb25JZDogXCIwM2RhMGUzMi0wNTg1LTQ3OWEtYjFkNi1kNTkzZGE5ZTZhZGJcIixcclxuICAgIEJyYW5jaENoYW5uZWxEZWZpbml0aW9uSWQ6IFwiNjFlOTYxNTYtMTZlOC00ZWM4LTk0ZTktYWFhYWQwMWU0OTRkXCJcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IE9wcG9ydHVuaXR5QXNzaWdubWVudENvbnN0YW50ID0ge1xyXG4gICAgT3Bwb3J0dW5pdHlPd25lckFzc2lnbm1lbnRDdXN0b21BUEk6IFwib3RwcmNjcm1fb3Bwb3J0dW5pdHlhc3NpZ25tZW50YXBpXCIsXHJcbiAgICBVc2VyR3JpZE5hbWU6IFwic3ViZ3JpZF9zZWxlY3RfdXNlclwiLFxyXG4gICAgVGVhbUdyaWROYW1lOiBcInN1YmdyaWRfc2VsZWN0X3RlYW1cIixcclxuICAgIFNpZGVQYW5lTmFtZTogXCJvdHBfYXNzaWdubWVudF9wYW5lXCJcclxufVxyXG5cclxuZXhwb3J0IGNvbnN0IEVudmlyb25tZW50VmFyaWFibGVOYW1lID0ge1xyXG4gICAgQ2VjaWxJRE1pc3NpbmdFcnJvcjogXCJvdHByY2NybV9jZWNpbGlkbWlzc2luZ2Vycm9yXCIsXHJcbiAgICBDZWNpbElkSW52YWxpZEVycm9yOiBcIm90cHJjY3JtX2NlY2lsaWRub3Rmb3VuZGVycm9yXCJcclxufSIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0obW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCIvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9ucyBmb3IgaGFybW9ueSBleHBvcnRzXG5fX3dlYnBhY2tfcmVxdWlyZV9fLmQgPSAoZXhwb3J0cywgZGVmaW5pdGlvbikgPT4ge1xuXHRmb3IodmFyIGtleSBpbiBkZWZpbml0aW9uKSB7XG5cdFx0aWYoX193ZWJwYWNrX3JlcXVpcmVfXy5vKGRlZmluaXRpb24sIGtleSkgJiYgIV9fd2VicGFja19yZXF1aXJlX18ubyhleHBvcnRzLCBrZXkpKSB7XG5cdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywga2V5LCB7IGVudW1lcmFibGU6IHRydWUsIGdldDogZGVmaW5pdGlvbltrZXldIH0pO1xuXHRcdH1cblx0fVxufTsiLCJfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSAob2JqLCBwcm9wKSA9PiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCkpIiwiLy8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuX193ZWJwYWNrX3JlcXVpcmVfXy5yID0gKGV4cG9ydHMpID0+IHtcblx0aWYodHlwZW9mIFN5bWJvbCAhPT0gJ3VuZGVmaW5lZCcgJiYgU3ltYm9sLnRvU3RyaW5nVGFnKSB7XG5cdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFN5bWJvbC50b1N0cmluZ1RhZywgeyB2YWx1ZTogJ01vZHVsZScgfSk7XG5cdH1cblx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsICdfX2VzTW9kdWxlJywgeyB2YWx1ZTogdHJ1ZSB9KTtcbn07IiwiaW1wb3J0IHsgQXR0cmlidXRlcywgZm9ybVR5cGUgfSBmcm9tIFwiLi9jb25zdGFudHNcIjtcclxuXHJcbmV4cG9ydCBjbGFzcyBGb3JtSGVscGVyIHtcclxuICAgIHN0YXRpYyBTZXRDdXJyZW50TG9nZ2VkSW5Vc2VySW5Mb29rdXBGaWVsZChjb250ZXh0OiBhbnksIGZpZWxkTmFtZTogc3RyaW5nKSB7XHJcbiAgICAgICAgbGV0IHNldFVzZXJ2YWx1ZSA9IG5ldyBBcnJheSgpO1xyXG4gICAgICAgIHNldFVzZXJ2YWx1ZVswXSA9IG5ldyBPYmplY3QoKTtcclxuICAgICAgICBzZXRVc2VydmFsdWVbMF0uaWQgPSBYcm0uVXRpbGl0eS5nZXRHbG9iYWxDb250ZXh0KCkudXNlclNldHRpbmdzLnVzZXJJZDtcclxuICAgICAgICBzZXRVc2VydmFsdWVbMF0uZW50aXR5VHlwZSA9ICdzeXN0ZW11c2VyJztcclxuICAgICAgICBzZXRVc2VydmFsdWVbMF0ubmFtZSA9IFhybS5VdGlsaXR5LmdldEdsb2JhbENvbnRleHQoKS51c2VyU2V0dGluZ3MudXNlck5hbWU7XHJcbiAgICAgICAgY29udGV4dC5nZXRBdHRyaWJ1dGUoZmllbGROYW1lKS5zZXRWYWx1ZShzZXRVc2VydmFsdWUpXHJcbiAgICB9XHJcblxyXG4gICAgc3RhdGljIFByb2dyYW1tZV9PbmxvYWRUb1NldExvZ2dlZEluVXNlcihjb250ZXh0OiBhbnkpIHsgICAgICAgIFxyXG4gICAgICAgIGlmIChjb250ZXh0LmdldEZvcm1Db250ZXh0KCkudWkuZ2V0Rm9ybVR5cGUoKSA9PT0gZm9ybVR5cGUuQ3JlYXRlKSB7XHJcbiAgICAgICAgICAgIGNvbnN0IGZvcm1Db250ZXh0Q3VzdG9tID0gY29udGV4dC5nZXRGb3JtQ29udGV4dCgpO1xyXG4gICAgICAgICAgICBGb3JtSGVscGVyLlNldEN1cnJlbnRMb2dnZWRJblVzZXJJbkxvb2t1cEZpZWxkKGZvcm1Db250ZXh0Q3VzdG9tLCBBdHRyaWJ1dGVzLlByb2dyYW1tZS5Pd25lcik7XHJcbiAgICAgICAgfVxyXG4gICAgfVxyXG4gICAgLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXHJcbiAgIC8vLyBzdHJpcCB0aGUgYnJhY2VzIG9mIGd1aWRcclxuICAgLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXHJcblxyXG4gc3RhdGljIHN0cmlwQnJhY2VzKGd1aWQ6IHN0cmluZyB8IHVuZGVmaW5lZCB8IG51bGwpOiBzdHJpbmcge1xyXG4gICAgICAgaWYgKCFndWlkKSByZXR1cm4gXCJcIjtcclxuICAgICAgIHJldHVybiBndWlkLnJlcGxhY2UoXCJ7XCIsIFwiXCIpLnJlcGxhY2UoXCJ9XCIsIFwiXCIpO1xyXG4gICB9XHJcblxyXG4gICAvLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cclxuICAgLy8vIEJ1aWxkIHF1ZXJ5IHN0cmluZ1xyXG4gICAvLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cclxuICAgIHN0YXRpYyBidWlsZFF1ZXJ5KHBhcmFtczogUmVjb3JkPHN0cmluZywgc3RyaW5nIHwgdW5kZWZpbmVkIHwgbnVsbD4pOiBzdHJpbmcge1xyXG4gICAgICAgY29uc3QgcGFydHM6IHN0cmluZ1tdID0gW107XHJcbiAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhwYXJhbXMpKSB7XHJcbiAgICAgICAgICAgY29uc3QgdmFsdWUgPSBwYXJhbXNba2V5XSA/PyBcIlwiO1xyXG4gICAgICAgICAgIHBhcnRzLnB1c2goYCR7ZW5jb2RlVVJJQ29tcG9uZW50KGtleSl9PSR7ZW5jb2RlVVJJQ29tcG9uZW50KHZhbHVlKX1gKTtcclxuICAgICAgIH1cclxuICAgICAgIHJldHVybiBwYXJ0cy5qb2luKFwiJlwiKTtcclxuXHJcbiAgIH1cclxuXHJcbiAgIC8vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxyXG4gICAvLy8gR2V0IEJTUyBjb25maWcgY29kZSByZWxhdGVkIHRvIHByb2R1Y3RcclxuICAgLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXHJcblxyXG4gICAgc3RhdGljIGFzeW5jIGdldEJzc0NvbmZpZ3VyYXRpb25zRmV0Y2hYbWwocHJvZHVjdElkOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZ1tdPiB7XHJcbiAgICAgICBjb25zdCBmZXRjaFhtbCA9IGBcclxuICAgIDxmZXRjaD5cclxuICAgICAgPGVudGl0eSBuYW1lPVwib3RwcmNjcm1fYnNzY29uZmlndXJhdGlvbnNcIj5cclxuICAgICAgICA8YXR0cmlidXRlIG5hbWU9XCJvdHByY2NybV9jb2RlXCIgLz5cclxuICAgICAgIDxsaW5rLWVudGl0eSBuYW1lPVwib3RwcmNjcm1fcHJvZHVjdF9vdHByY2NybV9ic3Njb25maWd1cmF0aW9uc1wiIGZyb209XCJvdHByY2NybV9ic3Njb25maWd1cmF0aW9uc2lkXCIgdG89XCJvdHByY2NybV9ic3Njb25maWd1cmF0aW9uc2lkXCIgdmlzaWJsZT1cImZhbHNlXCIgaW50ZXJzZWN0PVwidHJ1ZVwiPlxyXG4gICAgICA8bGluay1lbnRpdHkgbmFtZT1cInByb2R1Y3RcIiBmcm9tPVwicHJvZHVjdGlkXCIgdG89XCJwcm9kdWN0aWRcIiBhbGlhcz1cImFkXCI+XHJcbiAgICA8ZmlsdGVyIHR5cGU9XCJhbmRcIj5cclxuICAgPGNvbmRpdGlvbiBhdHRyaWJ1dGU9XCJwcm9kdWN0aWRcIiBvcGVyYXRvcj1cImVxXCIgdmFsdWU9XCIke3Byb2R1Y3RJZH1cIiAvPlxyXG4gIDwvZmlsdGVyPlxyXG4gICAgICAgIDwvbGluay1lbnRpdHk+XHJcbiAgPC9saW5rLWVudGl0eT5cclxuICA8L2VudGl0eT5cclxuPC9mZXRjaD4gICAgICBcclxuYDtcclxuXHJcbiAgICAgICBjb25zdCByZWxhdGVkQ29kZXM6IHN0cmluZ1tdID0gW107XHJcbiAgICAgICB0cnkge1xyXG4gICAgICAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgWHJtLldlYkFwaS5yZXRyaWV2ZU11bHRpcGxlUmVjb3JkcyhcIm90cHJjY3JtX2Jzc2NvbmZpZ3VyYXRpb25zXCIsIGA/ZmV0Y2hYbWw9JHtlbmNvZGVVUklDb21wb25lbnQoZmV0Y2hYbWwpfWApO1xyXG4gICAgICAgICAgIHJlc3BvbnNlLmVudGl0aWVzLmZvckVhY2goKGVudGl0eTogYW55KSA9PiB7XHJcbiAgICAgICAgICAgICAgIGlmIChlbnRpdHkub3RwcmNjcm1fY29kZSkge1xyXG4gICAgICAgICAgICAgICAgICAgcmVsYXRlZENvZGVzLnB1c2goZW50aXR5Lm90cHJjY3JtX2NvZGUpO1xyXG4gICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgfSk7XHJcbiAgICAgICB9IGNhdGNoIChlcnJvcikge1xyXG4gICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJFcnJvciBmZXRjaGluZyBCU1MgY29uZmlndXJhdGlvbnM6XCIsIGVycm9yKTtcclxuICAgICAgIH1cclxuXHJcbiAgICAgICByZXR1cm4gcmVsYXRlZENvZGVzO1xyXG4gICB9XHJcblxyXG4gICAvLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cclxuICAgLy8vIEJ1aWxkIGFwcG9pbnRtZW50IGNvbmZpZ3VyYXRpb25cclxuICAgLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXHJcblxyXG4gICAgc3RhdGljIGJ1aWxkQXBwb2ludG1lbnRDb25maWcocmVsYXRlZENvZGVzOiBzdHJpbmdbXSk6IHN0cmluZyB7XHJcbiAgICAgICBjb25zdCBwYXJhbXMgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKCk7XHJcbiAgICAgICAgICAgIGxldCBmaXJzdERvbmUgPSBmYWxzZTtcclxuICAgICAgIFxyXG4gICAgZm9yIChjb25zdCByYXcgb2YgcmVsYXRlZENvZGVzID8/IFtdKSB7XHJcbiAgICBjb25zdCBjb2RlID0gKHJhdyA/PyBcIlwiKS50b1N0cmluZygpLnRyaW0oKTtcclxuICAgIGlmICghY29kZSkgY29udGludWU7IC8vIHNraXAgZW1wdGllc1xyXG5cclxuICAgICAgaWYgKCFmaXJzdERvbmUpIHtcclxuICAgICAgLy8gJ3NldCcgZW5zdXJlcyB0aGUgZmlyc3QgdmFsdWUgaXMgYXNzaWduZWQgZm9yIHRoZSBrZXkgKHJlcGxhY2VzIGlmIGV4aXN0ZWQpXHJcbiAgICAgIHBhcmFtcy5zZXQoXCJwX2FwcG9pbnRtZW50X2NvbmZpZ1wiLCBjb2RlKTtcclxuICAgICAgZmlyc3REb25lID0gdHJ1ZTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIC8vIHN1YnNlcXVlbnQgdmFsdWVzIGFyZSBhcHBlbmRlZCAocmVwZWF0ZWQga2V5KVxyXG4gICAgICBwYXJhbXMuYXBwZW5kKFwicF9hcHBvaW50bWVudF9jb25maWdcIiwgIGNvZGUpO1xyXG4gICAgfSAgICBcclxuICAgfVxyXG4gICByZXR1cm4gcGFyYW1zLnRvU3RyaW5nKCk7IC8vIG5vIGxlYWRpbmcgXCI/XCJcclxuICAgfVxyXG5cclxuICAgLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXHJcbiAgIC8vLyBHZXQgZW52aXJvbm1lbnQgdmFyaWFibGUgdmFsdWUgZnJvbSBDUk1cclxuICAgLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXHJcbiAgIHN0YXRpYyBhc3luYyBnZXRFbnZpcm9ubWVudFZhcmlhYmxlcyhcclxuICAgICAgICB2YXJpYWJsZU5hbWVzOiBzdHJpbmdbXVxyXG4gICAgKTogUHJvbWlzZTxSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+PiB7XHJcblxyXG4gICAgICAgIGNvbnN0IHJlc3VsdDogUmVjb3JkPHN0cmluZywgc3RyaW5nPiA9IHt9O1xyXG5cclxuICAgICAgICBpZiAoIXZhcmlhYmxlTmFtZXMgfHwgdmFyaWFibGVOYW1lcy5sZW5ndGggPT09IDApIHtcclxuICAgICAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIC8vIEJ1aWxkIE9SIGZpbHRlclxyXG4gICAgICAgIGNvbnN0IGZpbHRlciA9IHZhcmlhYmxlTmFtZXNcclxuICAgICAgICAgICAgLm1hcCh2ID0+IGBzY2hlbWFuYW1lIGVxICcke3Z9J2ApXHJcbiAgICAgICAgICAgIC5qb2luKFwiIG9yIFwiKTtcclxuXHJcbiAgICAgICAgY29uc3QgcXVlcnkgPSBgPyRzZWxlY3Q9c2NoZW1hbmFtZVxyXG4gICAgICAgICAgICAmJGV4cGFuZD1lbnZpcm9ubWVudHZhcmlhYmxlZGVmaW5pdGlvbl9lbnZpcm9ubWVudHZhcmlhYmxldmFsdWUoJHNlbGVjdD12YWx1ZSlcclxuICAgICAgICAgICAgJiRmaWx0ZXI9JHtmaWx0ZXJ9YDtcclxuXHJcbiAgICAgICAgdHJ5IHtcclxuICAgICAgICAgICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCBYcm0uV2ViQXBpLnJldHJpZXZlTXVsdGlwbGVSZWNvcmRzKFxyXG4gICAgICAgICAgICAgICAgXCJlbnZpcm9ubWVudHZhcmlhYmxlZGVmaW5pdGlvblwiLFxyXG4gICAgICAgICAgICAgICAgcXVlcnlcclxuICAgICAgICAgICAgKTtcclxuXHJcbiAgICAgICAgICAgIGZvciAoY29uc3QgZW50aXR5IG9mIHJlc3BvbnNlLmVudGl0aWVzKSB7XHJcbiAgICAgICAgICAgICAgICBjb25zdCBzY2hlbWFOYW1lID0gZW50aXR5LnNjaGVtYW5hbWU7XHJcbiAgICAgICAgICAgICAgICBjb25zdCB2YWx1ZXMgPSAoZW50aXR5IGFzIGFueSkuZW52aXJvbm1lbnR2YXJpYWJsZWRlZmluaXRpb25fZW52aXJvbm1lbnR2YXJpYWJsZXZhbHVlO1xyXG5cclxuICAgICAgICAgICAgICAgIGlmICh2YWx1ZXMgJiYgdmFsdWVzLmxlbmd0aCA+IDApIHtcclxuICAgICAgICAgICAgICAgICAgICByZXN1bHRbc2NoZW1hTmFtZV0gPSB2YWx1ZXNbMF0udmFsdWUgPz8gXCJcIjtcclxuICAgICAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgICAgICAgcmVzdWx0W3NjaGVtYU5hbWVdID0gXCJcIjtcclxuICAgICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgLy8gTWFyayBtaXNzaW5nIHZhcmlhYmxlc1xyXG4gICAgICAgICAgICB2YXJpYWJsZU5hbWVzLmZvckVhY2gobmFtZSA9PiB7XHJcbiAgICAgICAgICAgICAgICBpZiAoIXJlc3VsdC5oYXNPd25Qcm9wZXJ0eShuYW1lKSkge1xyXG4gICAgICAgICAgICAgICAgICAgIHJlc3VsdFtuYW1lXSA9IFwiXCI7XHJcbiAgICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIH0pO1xyXG5cclxuICAgICAgICB9IGNhdGNoIChlcnIpIHtcclxuICAgICAgICAgICAgY29uc29sZS5lcnJvcihcIkVycm9yIGZldGNoaW5nIGVudmlyb25tZW50IHZhcmlhYmxlczpcIiwgZXJyKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIHJldHVybiByZXN1bHQ7XHJcbiAgICB9XHJcblxyXG5cclxuICAgLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXHJcbiAgIC8vLyBSZXRyaWV2ZSBjb250YWN0IGRldGFpbHMgKENlY2lsSUQgYW5kIGZ1bGxuYW1lKVxyXG4gICAvLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cclxuICAgc3RhdGljIGFzeW5jIHJldHJpZXZlQ29udGFjdERldGFpbHMoY3VzdG9tZXJJZDogc3RyaW5nKTogUHJvbWlzZTx7IGNlY2lsSWQ6IHN0cmluZyB8IHVuZGVmaW5lZDsgY3VzdG9tZXJOYW1lOiBzdHJpbmcgfCB1bmRlZmluZWQgfT4ge1xyXG4gICAgICAgY29uc3QgY29udGFjdCA9IGF3YWl0IFhybS5XZWJBcGkucmV0cmlldmVSZWNvcmQoXHJcbiAgICAgICAgICAgXCJjb250YWN0XCIsXHJcbiAgICAgICAgICAgY3VzdG9tZXJJZCxcclxuICAgICAgICAgICBcIj8kc2VsZWN0PW90cHJjY3JtX2NlY2lsaWQsZnVsbG5hbWVcIlxyXG4gICAgICAgKTtcclxuXHJcbiAgICAgICBjb25zdCBjZWNpbElkOiBzdHJpbmcgfCB1bmRlZmluZWQgPSAoY29udGFjdCBhcyBhbnkpLm90cHJjY3JtX2NlY2lsaWQ7XHJcbiAgICAgICBjb25zdCBjdXN0b21lck5hbWU6IHN0cmluZyB8IHVuZGVmaW5lZCA9IChjb250YWN0IGFzIGFueSkuZnVsbG5hbWU7XHJcblxyXG4gICAgICAgaWYgKCFjZWNpbElkKSB7XHJcbiAgICAgICAgICAgLy8gU2hvdyBpbmZvIGJ1dCBjb250aW51ZSAoeW91ciBvcmlnaW5hbCBjb2RlIGRpZCBub3QgcmV0dXJuKVxyXG4gICAgICAgICAgIGF3YWl0IFhybS5OYXZpZ2F0aW9uLm9wZW5BbGVydERpYWxvZyh7IHRleHQ6IFwiQ2VjaWxJRCBub3QgZm91bmQgb24gcmVsYXRlZCBDb250YWN0LlwiIH0pO1xyXG4gICAgICAgfVxyXG5cclxuICAgICAgIHJldHVybiB7IGNlY2lsSWQsIGN1c3RvbWVyTmFtZSB9O1xyXG4gICB9XHJcbi8vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxyXG4gICAvLy8gQnVpbGQgZmluYWwgVVJMIHdpdGggcXVlcnkgcGFyYW1ldGVyc1xyXG4gICAvLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cclxuICAgIHN0YXRpYyBhc3luYyBidWlsZEZpbmFsVXJsKG9wdGlvbnM6IHtcclxuICAgICAgIG9wcG9ydHVuaXR5SWQ6IHN0cmluZztcclxuICAgICAgIG9wcG9ydHVuaXR5TmFtZTogc3RyaW5nO1xyXG4gICAgICAgcmVjb3JkVXJsOiBzdHJpbmc7XHJcbiAgICAgICBjZWNpbElkOiBzdHJpbmcgfCB1bmRlZmluZWQ7XHJcbiAgICAgICBjdXN0b21lck5hbWU6IHN0cmluZyB8IHVuZGVmaW5lZDtcclxuICAgICAgIGFwcG9pbnRtZW50Q29kZT86IHN0cmluZztcclxuICAgICAgIHF1ZXJ5U3RyaW5nQlNTQ29kZXM6IHN0cmluZztcclxuICAgICAgICB9KTogUHJvbWlzZTxzdHJpbmc+IHtcclxuXHJcbiAgICAgICBjb25zdCBlbnZpcm9ubWVudFZhbHVlcyA9IGF3YWl0IEZvcm1IZWxwZXIuZ2V0RW52aXJvbm1lbnRWYXJpYWJsZXMoW1xyXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcIm90cHJjY3JtX2Jzc2NhbGxiYWNrdXJsXCIsXHJcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFwib3RwcmNjcm1fYnNzYmFzZXVybFwiXSk7XHJcblxyXG5cclxuICAgICAgIC8vIC0tLSBFeHRlcm5hbCBCYXNlIFVSTCAtLS1cclxuICAgICAgIC8vY29uc3QgYmFzZVVybCA9IFwiaHR0cHM6Ly9hcHAuZGV2LmZpb2tlcnQub2NwLm90cGJhbmsuaHUvY2FsbC1oYW5kbGVyXCI7XHJcbiAgICAgICAgIGNvbnN0IGJhc2VVcmwgPSBlbnZpcm9ubWVudFZhbHVlcy5vdHByY2NybV9ic3NiYXNldXJsO1xyXG4gICAgICAgLy8gLS0tIEZldGNoIGNhbGxiYWNrIFVSTCBmcm9tIGVudmlyb25tZW50IHZhcmlhYmxlIC0tLVxyXG4gICAgICAgY29uc3QgY2FsbGJhY2tVcmwgPSBlbnZpcm9ubWVudFZhbHVlcy5vdHByY2NybV9ic3NjYWxsYmFja3VybDtcclxuICAgICAgIGNvbnN0IHJhd0NhbGxiYWNrVXJsID0gYCR7Y2FsbGJhY2tVcmx9P29wcG9ydHVuaXR5aWQ9JHtlbmNvZGVVUklDb21wb25lbnQob3B0aW9ucy5vcHBvcnR1bml0eUlkKX1gO1xyXG4gICAgICAgLy9jb25zdCBlbmNvZGVkQ2FsbGJhY2tVcmwgPSBlbmNvZGVVUklDb21wb25lbnQocmF3Q2FsbGJhY2tVcmwpO1xyXG4gICAgICAgLy8gLS0tIEJ1aWxkIHF1ZXJ5IHBhcmFtZXRlcnMgKGtlZXAgdGhlbSBzbWFsbCAmIFVSTC1lbmNvZGVkKSAtLS1cclxuICAgICAgIGNvbnN0IHF1ZXJ5ID0gRm9ybUhlbHBlci5idWlsZFF1ZXJ5KHtcclxuICAgICAgICAgICBwX2V4dF9sZWFkX25hbWU6IG9wdGlvbnMub3Bwb3J0dW5pdHlOYW1lLFxyXG4gICAgICAgICAgIC8vIFRPRE86IHJldmlzaXQgcF9leHRfbGVhZF9kZXRhaWxzXHJcbiAgICAgICAgICAgcF9leHRfbGVhZF9kZXRhaWxzOiBcIkthdHRpbnRzIGEgbGlua3JlIGF6IMOpcmRla2zFkWTDqXMgcsOpc3psZXRlacOpcnQuXCIsXHJcbiAgICAgICAgICAgcF9leHRfbGVhZF91cmw6IG9wdGlvbnMucmVjb3JkVXJsLFxyXG4gICAgICAgICAgIHBfY2FsbGVyX3N5c3RlbTogXCJSQ0NSTVwiLFxyXG4gICAgICAgICAgIHBfYWN0aW9uOiBcImFwcG9pbnRtZW50LWV4dFwiLFxyXG4gICAgICAgICAgIHBfY2VjaWxfc3lzdGVtX2NvZGU6IG9wdGlvbnMuY2VjaWxJZCA/PyBcIlwiLFxyXG4gICAgICAgICAgIHBfY3VzdG9tZXJfbmFtZTogb3B0aW9ucy5jdXN0b21lck5hbWUgPz8gXCJcIixcclxuICAgICAgICAgICBwX2V4dF9kYXRhX25hbWU6IFwib3Bwb3J0dW5pdHlpZFwiLFxyXG4gICAgICAgICAgIC8vIFJFUVVJUkVEXHJcbiAgICAgICAgICAgcF9leHRfZGF0YV92YWx1ZTogb3B0aW9ucy5vcHBvcnR1bml0eUlkLFxyXG4gICAgICAgICAgIHBfY2FsbGJhY2tfdXJsOiByYXdDYWxsYmFja1VybCxcclxuICAgICAgICAgICBwX2NhbGxiYWNrX3RhcmdldDogXCJfU2VsZlwiLFxyXG4gICAgICAgICAgIHBfY2FsbGJhY2tfbWV0aG9kOiBcIkdFVFwiLFxyXG4gICAgICAgICAgIHBfYXBwb2ludG1lbnRfY29kZTogb3B0aW9ucy5hcHBvaW50bWVudENvZGUsXHJcbiAgICAgICAgICAgcF9jb21tZW50X2VuYWJsZWQ6IFwiWVwiLFxyXG4gICAgICAgICAgIHBfZW1haWxfbm90aWZpZXJfZmw6IFwiWVwiLFxyXG4gICAgICAgICAgIHBfc21zX25vdGlmaWNhdGlvbl9mbDogXCJZXCIsXHJcbiAgICAgICAgICAgXHJcbiAgICAgICB9KTtcclxuICAgICAgIFxyXG4gICAgICAgLy8gQ29tYmluZSBiYXNlICsgcmVwZWF0ZWQgZnJhZ21lbnQgKG5vIGV4dHJhIFwiJlwiIGlzc3VlcylcclxuICAgICAgIGNvbnN0IGZpbmFsUXVlcnkgPSBbcXVlcnksIG9wdGlvbnMucXVlcnlTdHJpbmdCU1NDb2Rlc10uZmlsdGVyKEJvb2xlYW4pLmpvaW4oXCImXCIpO1xyXG5cclxuICAgICAgIHJldHVybiBgJHtiYXNlVXJsfT8ke2ZpbmFsUXVlcnl9YDtcclxuICAgfVxyXG4gICBcclxufSJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==