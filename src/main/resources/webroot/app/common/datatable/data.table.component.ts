import {Component, Input, OnChanges, ContentChild, QueryList, ContentChildren} from '@angular/core';

import {DataTableColumnDirective} from './data.table.column.directive';
import {DataTableRowDetailDirective} from './data.table.row.detail.directive';
import {DataTableColumnGroupDirective} from './data.table.column.group.directive';

@Component({
    moduleId: module.id,
    selector: 'data-table',
    templateUrl: 'data.table.component.html',
    styleUrls: ['data.table.component.css']
})
export class DataTableComponent implements OnChanges {

    @Input()
    public data: any[];

    @Input()
    public footer: any;

    @Input()
    public pageSize: number;

    @Input()
    public defaultOrdering: string[];

    @Input()
    public striped: boolean = true;

    @Input()
    public showFooter: boolean = true;

    public pageRows: any[];

    private currentPage: number = 1;

    private ordering: string[];

    public columns: DataTableColumnDirective[];

    @ContentChild(DataTableRowDetailDirective)
    public _rowDetailTemplate: DataTableRowDetailDirective;

    public _rowDetailTemplateColumns: DataTableColumnDirective[][];

    @ContentChildren(DataTableColumnDirective)
    public set columnTemplates(val: QueryList<DataTableColumnDirective>) {
        if (val) {
            this.columns = val.toArray();
        }
    }

    public get rowDetailTemplate(): DataTableColumnDirective[][] {
        if (this._rowDetailTemplate && !this._rowDetailTemplateColumns) {
            let rowDetailTemplate = [];
            this._rowDetailTemplate.columnGroups.forEach((item: DataTableColumnGroupDirective) => {
                rowDetailTemplate.push(item.columns.toArray());
            });
            if (!rowDetailTemplate.length) {
                delete this._rowDetailTemplateColumns;
            } else {
                this._rowDetailTemplateColumns = rowDetailTemplate;
            }
        }
        return this._rowDetailTemplateColumns;
    }

    public hasHeader(): boolean {
        if (this.columns) {
            return this.columns.some((column: DataTableColumnDirective) => {
                return !!column.title;
            });
        }
        return false;
    }

    public hasFooter(): boolean {
        if (this.columns) {
            return this.columns.some((column: DataTableColumnDirective) => {
                return !!column.footerTemplate;
            });
        }
        return false;
    }

    public ngOnChanges(): void {
        this.sort();
    }

    public updatePage(page: number) {
        if (!this.data) {
            return;
        }

        this.currentPage = page;
        if (!this.pageSize) {
            this.pageRows = this.data;
            return;
        }
        let firstIndex = (page - 1) * this.pageSize;
        let lastIndex = page * this.pageSize;
        this.pageRows = this.data.slice(firstIndex, lastIndex);
    }

    public sortRecords(sortingKey: string): void {
        if (!this.ordering) {
            this.ordering = [];
        }

        let defaultOrdering = this.defaultOrdering;
        if (!defaultOrdering) {
            defaultOrdering = [];
        }

        if (this.ordering[0] == sortingKey) {
            this.ordering = ['-' + sortingKey].concat(defaultOrdering);
        } else {
            this.ordering = [sortingKey].concat(defaultOrdering);
        }
        this.sort();
    }

    private sort(): void {
        if (!this.data) {
            return;
        }

        if (!this.ordering) {
            this.ordering = this.defaultOrdering;
        }

        if (!this.ordering) {
            this.ordering = [];
        }

        this.ordering.slice().reverse().forEach((sortingKey: string) => {
            let direction = 1;
            if (sortingKey.startsWith('-')) {
                sortingKey = sortingKey.slice(1);
                direction = -1
            }
            this.data.sort((a: any, b: any) => {
                let first = a[sortingKey];
                let second = b[sortingKey];

                if (first < second)
                    return -1 * direction;
                if (first > second)
                    return direction;
                return 0;
            });
        });
        this.updatePage(this.currentPage);
    }
}

