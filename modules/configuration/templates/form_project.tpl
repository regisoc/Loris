<script language="javascript" src="{$baseurl|default}/configuration/js/project.js">
</script>
<p>Use this page to manage the configuration of existing projects, or to add a new one.</p>
<p>To configure study cohorts <a href="{$baseurl|default}/configuration/cohort/">click here</a>.</p>

<div class="col-md-3">
<ul class="nav nav-pills nav-stacked" role="tablist" data-tabs="tabs">
    <li class="active"><a id="#projectnew{$ProjectID|default}" href="#projectnew" data-toggle="tab" class="active">New ProjectID</a></li>
    {foreach from=$projects key=ProjectID item=project name=configContent}
    <li><a id="#project{$ProjectID}" href="#project{$ProjectID}" data-toggle="tab">{$project.Name}</a></li>
    {/foreach}
</ul>
</div>

<div class="col-md-7">
    <div class="tab-content">
    {foreach from=$projects key=ProjectID item=project name=tabContent}
    <div id="project{$ProjectID}" class="tab-pane">
        <h2>{$project.Name} (ProjectID: {$ProjectID})</h2>
        <br>
        <form class="form-horizontal" role="form" method="post" id="form{$ProjectID}">
            <fieldset>
                <input type="hidden" name="ProjectID" value="{$ProjectID}" class="ProjectID">
                    <div class="form-group">
                        <div class="col-sm-12 col-md-3" data-toggle="tooltip" data-placement="right" title="{'Full descriptive title of the project'}">
                            <label class="col-sm-12 control-label">Project Name</label>
                        </div>
                        <div class="col-sm-12 col-md-9">
                            <input class="form-control projectName" name="Name" value="{$project.Name}">
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="col-sm-12 col-md-3" data-toggle="tooltip" data-placement="right" title="{'Short name of the project (4 characters or less)'}">
                            <label class="col-sm-12 control-label">Alias</label>
                        </div>
                        <div class="col-sm-12 col-md-9">
                            <input class="form-control projectAlias" name="Alias" value="{$project.Alias}">
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="col-sm-12 col-md-3" data-toggle="tooltip" data-placement="right" title="{'The target number will be used to generate the recruitment progress bar on the dashboard'}">
                            <label class="col-sm-12 control-label">Recruitment Target</label>
                        </div>
                        <div class="col-sm-12 col-md-9">
                            <input class="form-control projectrecruitmentTarget" name="recruitmentTarget" value="{$project.recruitmentTarget}">
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="col-sm-12 col-md-3" data-toggle="tooltip" data-placement="right" title="{'These cohorts will be automatically displayed for any candidate affiliated with this project at timepoint creation.'}">
                            <label class="col-sm-12 control-label">Affiliated Cohorts</label>
                        </div>
                        <div class="col-sm-12 col-md-9">
                            <select name="CohortIDs" class="form-control projectCohortIDs" multiple>
                              {foreach from=$cohorts key=CohortID item=cohort}
                                  {if $cohort|in_array:$project.projectCohorts}
                                      <option value="{$CohortID}" selected>{$cohort}</option>
                                  {else}
                                      <option value="{$CohortID}">{$cohort}</option>
                                  {/if}
                              {/foreach}
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="col-sm-offset-3 col-sm-9">
                            <button id="saveproject{$ProjectID}" class="btn btn-primary saveproject submit-area">Save</button>
                            <button class="btn btn-default submit-area" type="reset">Reset</button>
                            <label class="saveStatus"></label>
                        </div>
                    </div>

            </fieldset>
        </form>
    </div>
    {/foreach}
    <div id="projectnew" class="tab-pane active">
        <h2>New Project</h2>
        <br>
        <form class="form-horizontal" role="form" method="post" id="form{$ProjectID}">
            <fieldset>
                <input type="hidden" name="ProjectID" value="new" class="ProjectID">
                <div class="form-group">
                    <div class="col-sm-12 col-md-3" data-toggle="tooltip" data-placement="right" title="{'Full descriptive title of the project'}">
                        <label class="col-sm-12 control-label">Project Name</label>
                    </div>
                    <div class="col-sm-12 col-md-9">
                        <input class="form-control projectName" name="Name" placeholder="Please add a project title here" value="">
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-sm-12 col-md-3" data-toggle="tooltip" data-placement="right" title="{'Short name of the project (4 characters or less)'}">
                        <label class="col-sm-12 control-label">Alias</label>
                    </div>
                    <div class="col-sm-12 col-md-9">
                        <input class="form-control projectAlias" name="Alias" placeholder="Please add an alias here" value="">
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-sm-12 col-md-3" data-toggle="tooltip" data-placement="right" title="{'The target number will be used to generate the recruitment progress bar on the dashboard'}">
                        <label class="col-sm-12 control-label">Recruitment Target</label>
                    </div>
                    <div class="col-sm-12 col-md-9">
			            <input class="form-control projectrecruitmentTarget" name="recruitmentTarget" placeholder="Please add a recruitment target here" value="">
                    </div>
                </div>
                <div>
                  <div class="col-sm-12 col-md-3" data-toggle="tooltip" data-placement="right" title="{'These cohorts will be automatically displayed for any candidate affiliated with this project at timepoint creation.'}">
                    <label class="col-sm-12 control-label">Affiliated Cohorts</label>
                  </div>
                  <div class="col-sm-12 col-md-9">
                    <div class="col-sm-12 col-md-9">
                      <select name="CohortIDs" class="form-control projectCohortIDs" multiple>
                        {foreach from=$cohorts key=CohortID item=cohort}
                            <option value="{$CohortID}">{$cohort}</option>
                        {/foreach}
                      </select>
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-sm-offset-3 col-sm-9">
                        <button id="saveprojectnew" class="btn btn-primary saveproject submit-area">Save</button>
                        <button class="btn btn-default submit-area" type="reset">Reset</button>
                        <label class="saveStatus"></label>
                    </div>
                </div>

            </fieldset>
        </form>
    </div>
</div>
